# 🏰 Note Fortress

A secure, self-destructing note and code sharing website built with Python Flask and end-to-end encryption. Features a modern, minimalist interface inspired by leading security tools.

## ✨ Features

- **🔐 End-to-End Encryption**: Notes are encrypted in your browser using AES-256-GCM before being sent to the server
- **⏰ Time-Based Destruction**: Notes automatically expire and are deleted after a specified time (5 minutes to 1 week)
- **👁️ View-Based Destruction**: Set notes to self-destruct after a specific number of views (1-50)
- **🔒 Password Protection**: Optional password protection with bcrypt hashing for additional security
- **💻 Code Syntax Highlighting**: Automatic detection and highlighting for 15+ programming languages using Highlight.js
- **🌙 Dark/Light Mode**: Toggle between dark and light themes with persistent preference
- **🎨 Modern UI**: Clean, minimalist interface inspired by modern security tools
- **🛡️ Security Focused**: Comprehensive security headers, CSRF protection, HTTPS enforcement, and rate limiting
- **📱 Responsive Design**: Mobile-first responsive design that works seamlessly on all devices
- **🚫 Zero Knowledge**: Server cannot decrypt notes, no user accounts, IP logging, or persistent tracking

## 🔒 Security Features

- **Client-Side Encryption**: Encryption keys never leave your browser
- **Zero-Knowledge Architecture**: Server cannot decrypt note contents
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more
- **Rate Limiting**: Protection against abuse and spam
- **CSRF Protection**: Secure form submissions
- **Input Validation**: Comprehensive sanitization and validation

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- SQLite (included with Python)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/PrivateDonut/NoteFortress.git
   cd note-fortress
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` with your configuration:
   ```env
   SECRET_KEY=your-secure-secret-key-here
   DATABASE_PATH=notes.db
   MAX_NOTE_SIZE=1048576
   DEFAULT_TTL=3600
   MAX_TTL=604800
   RATE_LIMIT=10
   HTTPS_ONLY=false
   ```

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Open your browser**
   Navigate to `http://localhost:5000`

## 🎨 Design & User Interface

Note Fortress features a modern, clean interface designed for security and usability:

- **Minimalist Design**: Clean layout focusing on essential features without clutter
- **Professional Appearance**: Inspired by SecureNotes.net and Enclosed.cc for trustworthy aesthetics
- **Custom Components**: Hand-crafted form elements, buttons, and cards for consistent experience
- **CSS Variables**: Consistent color system supporting light and dark themes
- **Typography**: Inter font for excellent readability and professional appearance
- **Responsive Grid**: Mobile-first design that adapts seamlessly to all screen sizes
- **Subtle Animations**: Smooth transitions and hover effects for enhanced user experience

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key for sessions | Auto-generated |
| `DATABASE_PATH` | SQLite database file path | `notes.db` |
| `MAX_NOTE_SIZE` | Maximum note size in bytes | `1048576` (1MB) |
| `DEFAULT_TTL` | Default expiration time in seconds | `3600` (1 hour) |
| `MAX_TTL` | Maximum allowed expiration time | `604800` (1 week) |
| `RATE_LIMIT` | Rate limit per minute per IP | `10` |
| `HTTPS_ONLY` | Enforce HTTPS redirects | `false` |

### Database Schema

Note Fortress uses SQLite with minimal data storage:
- **notes** table: `id`, `encrypted_content`, `destruction_type`, `destruction_value`, `created_at`, `view_count`, `password_hash`, `max_views`
- No IP addresses, user agents, or tracking data stored
- Automatic cleanup of expired notes

## 🌐 Production Deployment

### Using Gunicorn

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using Docker

Create a `Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## 🔐 How Encryption Works

1. **Key Generation**: A random 256-bit AES key is generated in your browser
2. **Encryption**: Note content is encrypted using AES-GCM with a random IV
3. **Storage**: Only encrypted data is sent to and stored on the server
4. **Sharing**: The encryption key is embedded in the URL fragment (#key)
5. **Decryption**: The key is extracted from the URL and used to decrypt the note client-side

**Important**: The encryption key never leaves your browser and is not sent to the server.

## 🛠️ API Endpoints

### Create Note
```http
POST /api/create
Content-Type: application/json

{
  "content": "base64-encrypted-content",
  "destruction_mode": "time",
  "ttl": 3600,
  "password": "optional-password",
  "csrf_token": "csrf-token"
}
```

### Get Note
```http
POST /api/get/{note_id}
Content-Type: application/json

{
  "password": "optional-password"
}
```

### Get Note Stats
```http
GET /api/stats/{note_id}
```

## 📊 Monitoring

The application includes:
- Automatic cleanup of expired notes
- Comprehensive logging
- Rate limiting metrics
- Error handling and reporting

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## ⚠️ Security Considerations

- Always use HTTPS in production
- Keep SQLite database secure and not publicly accessible
- Regularly update dependencies
- Monitor for security advisories
- Consider implementing additional rate limiting at the network level
- Use a strong SECRET_KEY in production

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built with Flask and modern web technologies
- Uses Web Crypto API for client-side encryption
- Modern CSS with Inter font for clean typography
- Syntax highlighting powered by Highlight.js
- Inspired by SecureNotes.net and Enclosed.cc design patterns

---

**⚠️ Disclaimer**: While Note Fortress implements strong security measures, no system is 100% secure. Use at your own risk and do not share extremely sensitive information without additional precautions.
