# Production Deployment Guide

This guide covers security considerations and best practices for deploying the ML-DSA Certificate API in production.

## Security Configuration

### 1. CORS Policy

**Issue:** The default configuration allows all origins (`CORS(app)`), which is only suitable for development.

**Production Fix:**

Edit `api.py` line 24 to restrict CORS to your specific domains:

```python
# Replace the permissive CORS configuration with:
CORS(app, origins=[
    "https://yourdomain.com",
    "https://app.yourdomain.com"
])
```

Or use environment variables for flexibility:

```python
import os

allowed_origins = os.environ.get('CORS_ORIGINS', '').split(',')
CORS(app, origins=allowed_origins if allowed_origins else ['https://yourdomain.com'])
```

Then set the environment variable:
```bash
export CORS_ORIGINS="https://yourdomain.com,https://app.yourdomain.com"
```

### 2. Debug Mode

**Issue:** Debug mode exposes sensitive information and should never be enabled in production.

**Solution:** The API now uses the `FLASK_DEBUG` environment variable (defaults to False).

**Production:**
```bash
export FLASK_DEBUG=False
python3 api.py
```

**Development:**
```bash
export FLASK_DEBUG=True
python3 api.py
```

### 3. CSRF Protection

**Note:** Flask APIs typically don't need CSRF protection when:
- Used as a stateless REST API with token-based authentication
- Not using cookies for authentication
- Clients send proper authentication headers

**If you need CSRF protection**, install and configure Flask-WTF:

```bash
pip3 install Flask-WTF
```

```python
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-production')
csrf = CSRFProtect(app)

# Optionally exempt API endpoints if using API keys
@csrf.exempt
@app.route('/api/v1/certificate/generate', methods=['POST'])
def generate_certificate():
    # ... endpoint code
```

## Production Deployment Options

### Option 1: Gunicorn (Recommended)

```bash
# Install gunicorn
pip3 install gunicorn

# Run with 4 worker processes
gunicorn -w 4 -b 0.0.0.0:8000 api:app

# With SSL/TLS
gunicorn -w 4 -b 0.0.0.0:8443 \
  --certfile=/path/to/cert.pem \
  --keyfile=/path/to/key.pem \
  api:app

# With timeout for long-running operations
gunicorn -w 4 -b 0.0.0.0:8000 --timeout 120 api:app
```

### Option 2: uWSGI

```bash
# Install uwsgi
pip3 install uwsgi

# Run with uwsgi
uwsgi --http 0.0.0.0:8000 --module api:app --processes 4
```

### Option 3: Docker

See `API-README.md` for Docker deployment instructions.

## Authentication and Authorization

The current API has **no authentication**. For production, implement one of these:

### API Key Authentication

```python
from functools import wraps
from flask import request, jsonify
import os

API_KEYS = set(os.environ.get('API_KEYS', '').split(','))

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in API_KEYS:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/v1/certificate/generate', methods=['POST'])
@require_api_key
def generate_certificate():
    # ... endpoint code
```

Usage:
```bash
export API_KEYS="key1,key2,key3"
```

Client request:
```bash
curl -X POST http://api.example.com/api/v1/certificate/generate \
  -H "X-API-Key: key1" \
  -H "Content-Type: application/json" \
  -d '{"subject": "/CN=example.com"}'
```

### OAuth 2.0 / JWT

For enterprise deployments, consider:
- Flask-JWT-Extended
- Authlib
- Integration with OAuth providers (Auth0, Okta, etc.)

## Rate Limiting

Install and configure Flask-Limiter:

```bash
pip3 install Flask-Limiter
```

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"],
    storage_uri="redis://localhost:6379"  # Use Redis for distributed rate limiting
)

@app.route('/api/v1/certificate/generate', methods=['POST'])
@limiter.limit("10 per minute")
def generate_certificate():
    # ... endpoint code
```

## Reverse Proxy Configuration

### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Increase timeout for certificate generation
        proxy_read_timeout 120s;
        proxy_connect_timeout 120s;
    }
}
```

### Apache

```apache
<VirtualHost *:443>
    ServerName api.yourdomain.com

    SSLEngine on
    SSLCertificateFile /path/to/cert.pem
    SSLCertificateKeyFile /path/to/key.pem

    # Security headers
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"

    ProxyPass / http://127.0.0.1:8000/
    ProxyPassReverse / http://127.0.0.1:8000/
    
    ProxyTimeout 120
</VirtualHost>
```

## Logging and Monitoring

### Configure Proper Logging

```python
import logging
from logging.handlers import RotatingFileHandler

if not app.debug:
    # File handler
    file_handler = RotatingFileHandler('api.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('ML-DSA Certificate API startup')
```

### Never Log Private Keys

The current implementation already follows this best practice - private keys are never logged.

## Environment Variables

Create a `.env` file for production configuration:

```bash
# Flask Configuration
FLASK_DEBUG=False
SECRET_KEY=your-secret-key-here

# CORS Configuration
CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com

# API Keys (comma-separated)
API_KEYS=key1,key2,key3

# Rate Limiting
REDIS_URL=redis://localhost:6379

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/mldsa-api/api.log
```

Load environment variables:

```python
from dotenv import load_dotenv
load_dotenv()
```

Install python-dotenv:
```bash
pip3 install python-dotenv
```

## Systemd Service (Linux)

Create `/etc/systemd/system/mldsa-api.service`:

```ini
[Unit]
Description=ML-DSA Certificate API
After=network.target

[Service]
Type=notify
User=www-data
Group=www-data
WorkingDirectory=/opt/mldsa-cert
Environment="FLASK_DEBUG=False"
Environment="PATH=/opt/mldsa-cert/venv/bin"
ExecStart=/opt/mldsa-cert/venv/bin/gunicorn -w 4 -b 127.0.0.1:8000 --timeout 120 api:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable mldsa-api
sudo systemctl start mldsa-api
sudo systemctl status mldsa-api
```

## Security Checklist

- [ ] CORS restricted to specific domains
- [ ] Debug mode disabled (`FLASK_DEBUG=False`)
- [ ] HTTPS/TLS enabled
- [ ] API authentication implemented
- [ ] Rate limiting configured
- [ ] Input validation on all endpoints
- [ ] Proper error handling (no stack traces exposed)
- [ ] Security headers configured
- [ ] Logging configured (without sensitive data)
- [ ] Regular security updates
- [ ] Firewall rules configured
- [ ] Regular backups
- [ ] Monitoring and alerting set up

## Monitoring Certificate Generation

```python
from prometheus_flask_exporter import PrometheusMetrics

metrics = PrometheusMetrics(app)

# Custom metrics
cert_generation_counter = metrics.counter(
    'certificate_generation_total',
    'Total certificate generation requests',
    labels={'security_level': lambda: request.json.get('security_level', 'unknown')}
)
```

## Additional Resources

- [Flask Production Best Practices](https://flask.palletsprojects.com/en/latest/deploying/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Gunicorn Documentation](https://docs.gunicorn.org/)
- [Nginx Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)

## Support

For production deployment issues, consult:
- Main `README.md` for installation requirements
- `API-README.md` for API documentation
- `WARP.md` for development guidelines
