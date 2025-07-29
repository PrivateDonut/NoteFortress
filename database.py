import sqlite3
import uuid
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
import bcrypt
import os

class Database:
    def __init__(self, db_path='notes.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize the database with required tables"""
        with self.get_connection() as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS notes (
                    id TEXT PRIMARY KEY,
                    encrypted_content TEXT NOT NULL,
                    destruction_type TEXT NOT NULL,  -- 'time' or 'views'
                    destruction_value INTEGER NOT NULL,  -- timestamp or view count
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    view_count INTEGER DEFAULT 0,
                    password_hash TEXT,
                    max_views INTEGER
                )
            ''')
            
            # Create index for cleanup queries
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_destruction 
                ON notes(destruction_type, destruction_value)
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def create_note(self, encrypted_content, destruction_type, destruction_value, 
                   password=None, max_views=None):
        """Create a new note and return the note ID"""
        note_id = str(uuid.uuid4())
        password_hash = None
        
        if password:
            password_hash = bcrypt.hashpw(
                password.encode('utf-8'), 
                bcrypt.gensalt()
            ).decode('utf-8')
        
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO notes 
                (id, encrypted_content, destruction_type, destruction_value, 
                 password_hash, max_views)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (note_id, encrypted_content, destruction_type, destruction_value,
                  password_hash, max_views))
            conn.commit()
        
        return note_id
    
    def get_note(self, note_id, password=None):
        """Retrieve a note and increment view count"""
        with self.get_connection() as conn:
            # First, get the note
            cursor = conn.execute('''
                SELECT * FROM notes WHERE id = ?
            ''', (note_id,))
            
            note = cursor.fetchone()
            if not note:
                return None
            
            # Check if note has expired
            if self._is_note_expired(note):
                self.delete_note(note_id)
                return None
            
            # Verify password if required
            if note['password_hash']:
                if not password:
                    return {'error': 'password_required'}
                
                if not bcrypt.checkpw(password.encode('utf-8'), 
                                    note['password_hash'].encode('utf-8')):
                    return {'error': 'invalid_password'}
            
            # Check view limit
            if note['max_views'] and note['view_count'] >= note['max_views']:
                self.delete_note(note_id)
                return {'error': 'view_limit_exceeded'}
            
            # Increment view count
            new_view_count = note['view_count'] + 1
            conn.execute('''
                UPDATE notes SET view_count = ? WHERE id = ?
            ''', (new_view_count, note_id))
            
            # Check if should delete after this view
            if note['max_views'] and new_view_count >= note['max_views']:
                conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
                should_delete = True
            else:
                should_delete = False
            
            conn.commit()
            
            return {
                'id': note['id'],
                'encrypted_content': note['encrypted_content'],
                'created_at': note['created_at'],
                'view_count': new_view_count,
                'destruction_type': note['destruction_type'],
                'destruction_value': note['destruction_value'],
                'max_views': note['max_views'],
                'will_be_deleted': should_delete
            }
    
    def get_note_stats(self, note_id):
        """Get note statistics without incrementing view count"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM notes WHERE id = ?
            ''', (note_id,))
            
            note = cursor.fetchone()
            if not note:
                return None
            
            if self._is_note_expired(note):
                self.delete_note(note_id)
                return None
            
            stats = {
                'exists': True,
                'created_at': note['created_at'],
                'view_count': note['view_count'],
                'destruction_type': note['destruction_type'],
                'destruction_value': note['destruction_value'],
                'max_views': note['max_views'],
                'has_password': bool(note['password_hash'])
            }
            
            # Calculate time remaining for time-based destruction
            if note['destruction_type'] == 'time':
                expire_time = datetime.fromtimestamp(note['destruction_value'])
                time_remaining = (expire_time - datetime.now()).total_seconds()
                stats['time_remaining'] = max(0, int(time_remaining))
            
            # Calculate views remaining for view-based destruction
            if note['max_views']:
                stats['views_remaining'] = max(0, note['max_views'] - note['view_count'])
            
            return stats
    
    def delete_note(self, note_id):
        """Delete a specific note"""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM notes WHERE id = ?', (note_id,))
            conn.commit()
    
    def cleanup_expired_notes(self):
        """Remove expired notes from the database"""
        current_time = int(datetime.now().timestamp())
        
        with self.get_connection() as conn:
            # Delete time-based expired notes
            cursor = conn.execute('''
                DELETE FROM notes 
                WHERE destruction_type = 'time' AND destruction_value < ?
            ''', (current_time,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            
            return deleted_count
    
    def _is_note_expired(self, note):
        """Check if a note has expired"""
        if note['destruction_type'] == 'time':
            expire_time = datetime.fromtimestamp(note['destruction_value'])
            return datetime.now() > expire_time
        
        return False
    
    def get_database_stats(self):
        """Get general database statistics"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT COUNT(*) as total_notes FROM notes')
            total_notes = cursor.fetchone()['total_notes']
            
            cursor = conn.execute('''
                SELECT COUNT(*) as password_protected 
                FROM notes WHERE password_hash IS NOT NULL
            ''')
            password_protected = cursor.fetchone()['password_protected']
            
            return {
                'total_notes': total_notes,
                'password_protected': password_protected
            }