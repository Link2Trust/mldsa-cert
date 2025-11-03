# ML-DSA Certificate REST API

REST API for generating ML-DSA (post-quantum) X.509 certificates compliant with RFC 9881.

## Quick Start

### Installation

```bash
# Install API dependencies
pip3 install -r requirements-api.txt

# Start the API server
python3 api.py
```

The API will be available at `http://localhost:5000`

### Test the API

```bash
# Health check
curl http://localhost:5000/health

# Get API info
curl http://localhost:5000/api/v1/info
```

## API Endpoints

### 1. Health Check

**GET** `/health`

Check if the API is running.

**Response:**
```json
{
  "status": "healthy",
  "service": "ML-DSA Certificate API",
  "version": "1.0"
}
```

### 2. API Information

**GET** `/api/v1/info`

Get information about the API and supported algorithms.

**Response:**
```json
{
  "service": "ML-DSA Certificate Generator API",
  "version": "1.0",
  "rfc": "RFC 9881",
  "supported_algorithms": {
    "ml_dsa": ["ml-dsa-44", "ml-dsa-65", "ml-dsa-87"]
  },
  "endpoints": {
    "generate": "/api/v1/certificate/generate",
    "generate_csr": "/api/v1/csr/generate",
    "generate_keys": "/api/v1/keys/generate"
  }
}
```

### 3. Generate Key Pair

**POST** `/api/v1/keys/generate`

Generate an ML-DSA key pair.

**Request Body:**
```json
{
  "security_level": "ml-dsa-65"
}
```

**Parameters:**
- `security_level` (optional): `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87` (default: `ml-dsa-65`)

**Response:**
```json
{
  "private_key": "LS0tLS1CRUdJTi...",
  "public_key": "LS0tLS1CRUdJTi...",
  "security_level": "ml-dsa-65"
}
```

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/keys/generate \
  -H "Content-Type: application/json" \
  -d '{"security_level": "ml-dsa-65"}'
```

### 4. Generate Certificate

**POST** `/api/v1/certificate/generate`

Generate a self-signed ML-DSA certificate.

**Request Body:**
```json
{
  "subject": "/CN=example.com/O=Example Org/C=US",
  "security_level": "ml-dsa-65",
  "days": 365,
  "san": ["DNS:www.example.com", "DNS:example.com"],
  "is_ca": false
}
```

**Parameters:**
- `subject` (required): Certificate subject in DN format
- `security_level` (optional): ML-DSA security level (default: `ml-dsa-65`)
- `days` (optional): Validity period in days (default: 365, max: 7300)
- `san` (optional): Array of Subject Alternative Names
- `is_ca` (optional): Whether this is a CA certificate (default: false)

**Response:**
```json
{
  "certificate": "LS0tLS1CRUdJTi...",
  "private_key": "LS0tLS1CRUdJTi...",
  "public_key": "LS0tLS1CRUdJTi...",
  "security_level": "ml-dsa-65",
  "subject": "/CN=example.com/O=Example Org/C=US",
  "validity_days": 365
}
```

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/certificate/generate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "/CN=api.example.com/O=Example Corp",
    "security_level": "ml-dsa-65",
    "days": 730,
    "san": ["DNS:www.example.com", "DNS:api.example.com"]
  }'
```

### 5. Generate CSR

**POST** `/api/v1/csr/generate`

Generate a Certificate Signing Request (CSR).

**Request Body:**
```json
{
  "subject": "/CN=example.com/O=Example Org",
  "security_level": "ml-dsa-65",
  "san": ["DNS:www.example.com"]
}
```

**Parameters:**
- `subject` (required): Certificate subject
- `security_level` (optional): ML-DSA security level
- `san` (optional): Array of Subject Alternative Names

**Response:**
```json
{
  "csr": "LS0tLS1CRUdJTi...",
  "private_key": "LS0tLS1CRUdJTi...",
  "public_key": "LS0tLS1CRUdJTi...",
  "subject": "/CN=example.com/O=Example Org"
}
```

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/csr/generate \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "/CN=secure.example.com",
    "san": ["DNS:secure.example.com"]
  }'
```

## Response Format

All responses use Base64 encoding for certificate and key data. To decode:

```bash
# Save response to file
echo "LS0tLS1CRUdJTi..." | base64 -d > certificate.crt

# Or in Python
import base64
cert_data = base64.b64decode(response['certificate'])
```

## Error Responses

All errors return JSON with an `error` field:

```json
{
  "error": "Error message description"
}
```

**HTTP Status Codes:**
- `200` - Success
- `400` - Bad Request (invalid parameters)
- `404` - Endpoint not found
- `500` - Internal Server Error

## Security Considerations

### Production Deployment

1. **HTTPS Only**: Use HTTPS in production
2. **Authentication**: Implement API key or OAuth authentication
3. **Rate Limiting**: Add rate limiting to prevent abuse
4. **Input Validation**: Validate all input parameters
5. **Key Storage**: Never log or store private keys
6. **CORS**: Configure CORS properly for your domain

### Example Production Configuration

```python
# Use gunicorn for production
gunicorn -w 4 -b 0.0.0.0:8000 api:app

# With SSL
gunicorn -w 4 -b 0.0.0.0:8443 \
  --certfile=/path/to/cert.pem \
  --keyfile=/path/to/key.pem \
  api:app
```

## Docker Deployment

### Dockerfile

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY mldsa_cert.py .
COPY api.py .
COPY openssl-oqs.cnf .
COPY requirements-api.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements-api.txt

# Expose port
EXPOSE 5000

# Run API
CMD ["python3", "api.py"]
```

### Build and Run

```bash
# Build image
docker build -t mldsa-api .

# Run container
docker run -p 5000:5000 mldsa-api
```

## Example Client Code

### Python Client

```python
import requests
import base64
import json

API_URL = "http://localhost:5000"

# Generate certificate
response = requests.post(
    f"{API_URL}/api/v1/certificate/generate",
    json={
        "subject": "/CN=example.com",
        "security_level": "ml-dsa-65",
        "days": 365
    }
)

if response.status_code == 200:
    data = response.json()
    
    # Decode and save certificate
    cert = base64.b64decode(data['certificate'])
    with open('certificate.crt', 'wb') as f:
        f.write(cert)
    
    # Decode and save private key
    key = base64.b64decode(data['private_key'])
    with open('private.key', 'wb') as f:
        f.write(key)
    
    print("Certificate generated successfully!")
else:
    print(f"Error: {response.json()}")
```

### JavaScript/Node.js Client

```javascript
const axios = require('axios');
const fs = require('fs');

const API_URL = 'http://localhost:5000';

async function generateCertificate() {
    try {
        const response = await axios.post(
            `${API_URL}/api/v1/certificate/generate`,
            {
                subject: '/CN=example.com',
                security_level: 'ml-dsa-65',
                days: 365
            }
        );
        
        // Decode and save certificate
        const cert = Buffer.from(response.data.certificate, 'base64');
        fs.writeFileSync('certificate.crt', cert);
        
        // Decode and save private key
        const key = Buffer.from(response.data.private_key, 'base64');
        fs.writeFileSync('private.key', key);
        
        console.log('Certificate generated successfully!');
    } catch (error) {
        console.error('Error:', error.response?.data || error.message);
    }
}

generateCertificate();
```

### cURL Examples

```bash
# Generate certificate and save files
curl -X POST http://localhost:5000/api/v1/certificate/generate \
  -H "Content-Type: application/json" \
  -d '{"subject": "/CN=example.com", "days": 365}' \
  | jq -r '.certificate' \
  | base64 -d > certificate.crt
```

## Monitoring and Logging

The API logs all requests. In production, configure proper logging:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

## Rate Limiting

For production, add rate limiting:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/v1/certificate/generate', methods=['POST'])
@limiter.limit("10 per minute")
def generate_certificate():
    # ... endpoint code
```

## Testing

Run the test suite:

```bash
# Install test dependencies
pip3 install pytest requests

# Run tests
pytest test_api.py
```

## Support

For issues or questions:
- Check the main [README.md](README.md)
- Consult RFC 9881 for technical specifications

## License

See main README.md for license information.
