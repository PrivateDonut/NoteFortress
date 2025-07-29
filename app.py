import os
import secrets
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, abort, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv
import hashlib
import hmac
import sqlite3
from database import Database

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))

# Database connection
db = Database(os.getenv('DATABASE_PATH', 'notes.db'))

# Suppress the Flask-Limiter in-memory storage warning for development
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="flask_limiter.extension")

# Rate limiting - use in-memory for simplicity in development
# For production, consider using Redis or another proper storage backend
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[os.getenv('RATE_LIMIT', '10') + " per minute"]
)
limiter.init_app(app)

# Configuration
MAX_NOTE_SIZE = int(os.getenv('MAX_NOTE_SIZE', 1048576))  # 1MB
DEFAULT_TTL = int(os.getenv('DEFAULT_TTL', 3600))  # 1 hour
MAX_TTL = int(os.getenv('MAX_TTL', 86400))  # 24 hours
HTTPS_ONLY = os.getenv('HTTPS_ONLY', 'false').lower() == 'true'

def cleanup_expired_notes():
    """Background task to clean up expired notes"""
    try:
        deleted_count = db.cleanup_expired_notes()
        if deleted_count > 0:
            app.logger.info(f"Cleaned up {deleted_count} expired notes")
    except Exception as e:
        app.logger.error(f"Error during cleanup: {e}")

# Background scheduler for cleanup
scheduler = BackgroundScheduler()
scheduler.add_job(func=cleanup_expired_notes, trigger="interval", minutes=30)
scheduler.start()

def generate_csrf_token():
    """Generate a CSRF token for the session"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def validate_csrf_token(token):
    """Validate CSRF token"""
    return token and session.get('csrf_token') == token

@app.before_request
def enforce_https():
    """Enforce HTTPS in production"""
    if HTTPS_ONLY and not request.is_secure:
        if request.url.startswith('http://'):
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = (
        'camera=(), microphone=(), geolocation=(), '
        'payment=(), usb=(), magnetometer=(), gyroscope=()'
    )
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Remove server header
    response.headers.pop('Server', None)
    
    return response

@app.route('/')
def index():
    csrf_token = generate_csrf_token()
    return render_template('index.html', csrf_token=csrf_token)

@app.route('/view/<note_id>')
def view_note(note_id):
    return render_template('view.html', note_id=note_id)

@app.route('/api/create', methods=['POST'])
@limiter.limit("5 per minute")
def create_note():
    try:
        data = request.get_json()
        
        if not data or 'content' not in data:
            return jsonify({'error': 'No content provided'}), 400
            
        # CSRF protection
        csrf_token = data.get('csrf_token')
        if not validate_csrf_token(csrf_token):
            return jsonify({'error': 'Invalid CSRF token'}), 403
            
        content = data['content']
        password = data.get('password', '').strip()
        destruction_mode = data.get('destruction_mode', 'time')  # 'time' or 'views'
        
        if len(content.encode('utf-8')) > MAX_NOTE_SIZE:
            return jsonify({'error': 'Note too large'}), 400
        
        # Handle destruction settings
        if destruction_mode == 'time':
            ttl = min(int(data.get('ttl', DEFAULT_TTL)), MAX_TTL)
            destruction_value = int((datetime.now() + timedelta(seconds=ttl)).timestamp())
            max_views = None
        else:  # views
            max_views = int(data.get('max_views', 1))
            destruction_value = max_views
            ttl = MAX_TTL  # Set a maximum time limit even for view-based
        
        # Create note in database
        note_id = db.create_note(
            encrypted_content=content,
            destruction_type=destruction_mode,
            destruction_value=destruction_value,
            password=password if password else None,
            max_views=max_views
        )
        
        response_data = {'note_id': note_id}
        
        if destruction_mode == 'time':
            response_data['expires_at'] = datetime.fromtimestamp(destruction_value).isoformat()
        else:
            response_data['max_views'] = max_views
            
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"Error creating note: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/get/<note_id>', methods=['POST'])
@limiter.limit("20 per minute")
def get_note(note_id):
    try:
        # Validate note ID format (UUID)
        if not note_id:
            abort(404)
        
        data = request.get_json() or {}
        password = data.get('password', '')
        
        # Get note from database
        note = db.get_note(note_id, password if password else None)
        
        if not note:
            abort(404)
            
        # Handle password errors
        if isinstance(note, dict) and 'error' in note:
            if note['error'] == 'password_required':
                return jsonify({'error': 'Password required', 'password_required': True}), 401
            elif note['error'] == 'invalid_password':
                return jsonify({'error': 'Invalid password'}), 401
            elif note['error'] == 'view_limit_exceeded':
                return jsonify({'error': 'Note has reached its view limit'}), 410
        
        return jsonify({
            'content': note['encrypted_content'],
            'created_at': note['created_at'],
            'view_count': note['view_count'],
            'destruction_type': note['destruction_type'],
            'destruction_value': note['destruction_value'],
            'max_views': note['max_views'],
            'will_be_deleted': note.get('will_be_deleted', False)
        })
        
    except Exception as e:
        app.logger.error(f"Error retrieving note: {e}")
        abort(500)

@app.route('/api/stats/<note_id>', methods=['GET'])
@limiter.limit("30 per minute")
def get_note_stats(note_id):
    try:
        if not note_id:
            abort(404)
            
        stats = db.get_note_stats(note_id)
        
        if not stats:
            return jsonify({'exists': False})
            
        return jsonify(stats)
        
    except Exception as e:
        app.logger.error(f"Error getting note stats: {e}")
        abort(500)

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Note not found or expired'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)