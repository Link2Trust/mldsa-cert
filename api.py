#!/usr/bin/env python3
"""
ML-DSA Certificate REST API
Provides REST API endpoints for generating ML-DSA certificates.
"""

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import sys
import tempfile
import base64
from pathlib import Path
import json

# Import the certificate generator
from mldsa_cert import MLDSACertificateGenerator

app = Flask(__name__)

# CORS Configuration
# WARNING: This allows all origins. In production, restrict to specific domains:
# CORS(app, origins=["https://yourdomain.com"])
CORS(app)  # Development only - allows all origins

# Configuration
TEMP_DIR = tempfile.gettempdir()
MAX_VALIDITY_DAYS = 7300  # ~20 years
DEBUG_MODE = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

# File name constants
PRIVATE_KEY_FILENAME = 'private.key'
PUBLIC_KEY_FILENAME = 'public.pub'
CERTIFICATE_FILENAME = 'certificate.crt'
CSR_FILENAME = 'request.csr'

# Error message constants
ERR_PRIVATE_KEY_GENERATION = 'Failed to generate private key'
ERR_PUBLIC_KEY_GENERATION = 'Failed to generate public key'
ERR_SUBJECT_REQUIRED = 'Subject is required'


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'service': 'ML-DSA Certificate API',
        'version': '1.0'
    })


@app.route('/api/v1/info', methods=['GET'])
def info():
    """Get API information and supported algorithms."""
    return jsonify({
        'service': 'ML-DSA Certificate Generator API',
        'version': '1.0',
        'rfc': 'RFC 9881',
        'supported_algorithms': {
            'ml_dsa': ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'],
            'hybrid': ['rsa', 'ecdsa']
        },
        'endpoints': {
            'generate': '/api/v1/certificate/generate',
            'generate_csr': '/api/v1/csr/generate',
            'generate_keys': '/api/v1/keys/generate',
            'hybrid': '/api/v1/certificate/hybrid'
        }
    })


@app.route('/api/v1/keys/generate', methods=['POST'])
def generate_keys():
    """
    Generate ML-DSA key pair.
    
    Request body:
    {
        "security_level": "ml-dsa-65"  // optional, default: ml-dsa-65
    }
    
    Returns:
    {
        "private_key": "base64_encoded_private_key",
        "public_key": "base64_encoded_public_key",
        "security_level": "ml-dsa-65"
    }
    """
    try:
        data = request.get_json() or {}
        security_level = data.get('security_level', 'ml-dsa-65')
        
        # Validate security level
        if security_level not in ['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87']:
            return jsonify({'error': 'Invalid security level'}), 400
        
        # Create generator
        generator = MLDSACertificateGenerator(security_level)
        
        # Generate temporary files
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, PRIVATE_KEY_FILENAME)
            pub_file = os.path.join(tmpdir, PUBLIC_KEY_FILENAME)
            
            # Generate keys
            if not generator.generate_private_key(key_file):
                return jsonify({'error': ERR_PRIVATE_KEY_GENERATION}), 500
            
            if not generator.generate_public_key(key_file, pub_file):
                return jsonify({'error': ERR_PUBLIC_KEY_GENERATION}), 500
            
            # Read and encode keys
            with open(key_file, 'rb') as f:
                private_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(pub_file, 'rb') as f:
                public_key = base64.b64encode(f.read()).decode('utf-8')
        
        return jsonify({
            'private_key': private_key,
            'public_key': public_key,
            'security_level': security_level
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/certificate/generate', methods=['POST'])
def generate_certificate():
    """
    Generate self-signed ML-DSA certificate.
    
    Request body:
    {
        "subject": "/CN=example.com/O=Example Org/C=US",
        "security_level": "ml-dsa-65",  // optional
        "days": 365,  // optional
        "san": ["DNS:www.example.com", "DNS:example.com"],  // optional
        "is_ca": false  // optional
    }
    
    Returns:
    {
        "certificate": "base64_encoded_certificate",
        "private_key": "base64_encoded_private_key",
        "public_key": "base64_encoded_public_key",
        "security_level": "ml-dsa-65"
    }
    """
    try:
        data = request.get_json()
        
        # Required fields
        if 'subject' not in data:
            return jsonify({'error': ERR_SUBJECT_REQUIRED}), 400
        
        subject = data['subject']
        security_level = data.get('security_level', 'ml-dsa-65')
        days = data.get('days', 365)
        san_list = data.get('san')
        is_ca = data.get('is_ca', False)
        
        # Validate
        if days > MAX_VALIDITY_DAYS:
            return jsonify({'error': f'Max validity is {MAX_VALIDITY_DAYS} days'}), 400
        
        # Create generator
        generator = MLDSACertificateGenerator(security_level)
        
        # Generate in temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, PRIVATE_KEY_FILENAME)
            pub_file = os.path.join(tmpdir, PUBLIC_KEY_FILENAME)
            cert_file = os.path.join(tmpdir, CERTIFICATE_FILENAME)
            
            # Generate keys
            if not generator.generate_private_key(key_file):
                return jsonify({'error': ERR_PRIVATE_KEY_GENERATION}), 500
            
            if not generator.generate_public_key(key_file, pub_file):
                return jsonify({'error': ERR_PUBLIC_KEY_GENERATION}), 500
            
            # Generate certificate
            if not generator.generate_self_signed_certificate(
                key_file, cert_file, subject, days, san_list, is_ca
            ):
                return jsonify({'error': 'Failed to generate certificate'}), 500
            
            # Read and encode files
            with open(key_file, 'rb') as f:
                private_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(pub_file, 'rb') as f:
                public_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(cert_file, 'rb') as f:
                certificate = base64.b64encode(f.read()).decode('utf-8')
        
        return jsonify({
            'certificate': certificate,
            'private_key': private_key,
            'public_key': public_key,
            'security_level': security_level,
            'subject': subject,
            'validity_days': days
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/csr/generate', methods=['POST'])
def generate_csr():
    """
    Generate Certificate Signing Request (CSR).
    
    Request body:
    {
        "subject": "/CN=example.com/O=Example Org",
        "security_level": "ml-dsa-65",  // optional
        "san": ["DNS:www.example.com"]  // optional
    }
    
    Returns:
    {
        "csr": "base64_encoded_csr",
        "private_key": "base64_encoded_private_key",
        "public_key": "base64_encoded_public_key"
    }
    """
    try:
        data = request.get_json()
        
        if 'subject' not in data:
            return jsonify({'error': ERR_SUBJECT_REQUIRED}), 400
        
        subject = data['subject']
        security_level = data.get('security_level', 'ml-dsa-65')
        san_list = data.get('san')
        
        # Create generator
        generator = MLDSACertificateGenerator(security_level)
        
        # Generate in temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            key_file = os.path.join(tmpdir, PRIVATE_KEY_FILENAME)
            pub_file = os.path.join(tmpdir, PUBLIC_KEY_FILENAME)
            csr_file = os.path.join(tmpdir, CSR_FILENAME)
            
            # Generate keys
            if not generator.generate_private_key(key_file):
                return jsonify({'error': ERR_PRIVATE_KEY_GENERATION}), 500
            
            if not generator.generate_public_key(key_file, pub_file):
                return jsonify({'error': ERR_PUBLIC_KEY_GENERATION}), 500
            
            # Generate CSR
            if not generator.generate_csr(key_file, csr_file, subject, san_list):
                return jsonify({'error': 'Failed to generate CSR'}), 500
            
            # Read and encode files
            with open(key_file, 'rb') as f:
                private_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(pub_file, 'rb') as f:
                public_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(csr_file, 'rb') as f:
                csr = base64.b64encode(f.read()).decode('utf-8')
        
        return jsonify({
            'csr': csr,
            'private_key': private_key,
            'public_key': public_key,
            'subject': subject
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/v1/certificate/hybrid', methods=['POST'])
def generate_hybrid_certificate():
    """
    Generate hybrid certificate (ML-DSA + RSA/ECDSA).
    
    Request body:
    {
        "subject": "/CN=example.com/O=Example Org",
        "security_level": "ml-dsa-65",  // optional
        "classical_algorithm": "rsa",  // required: "rsa" or "ecdsa"
        "days": 365,  // optional
        "san": ["DNS:www.example.com"],  // optional
        "is_ca": false  // optional
    }
    
    Returns:
    {
        "ml_dsa_certificate": "base64_encoded",
        "classical_certificate": "base64_encoded",
        "ml_dsa_private_key": "base64_encoded",
        "ml_dsa_public_key": "base64_encoded",
        "classical_private_key": "base64_encoded",
        "classical_public_key": "base64_encoded",
        "security_level": "ml-dsa-65",
        "classical_algorithm": "rsa"
    }
    """
    try:
        data = request.get_json()
        
        # Required fields
        if 'subject' not in data:
            return jsonify({'error': ERR_SUBJECT_REQUIRED}), 400
        if 'classical_algorithm' not in data:
            return jsonify({'error': 'Classical algorithm is required (rsa or ecdsa)'}), 400
        
        subject = data['subject']
        security_level = data.get('security_level', 'ml-dsa-65')
        classical_algo = data['classical_algorithm']
        days = data.get('days', 365)
        san_list = data.get('san')
        is_ca = data.get('is_ca', False)
        
        # Validate
        if classical_algo not in ['rsa', 'ecdsa']:
            return jsonify({'error': 'Classical algorithm must be "rsa" or "ecdsa"'}), 400
        
        if days > MAX_VALIDITY_DAYS:
            return jsonify({'error': f'Max validity is {MAX_VALIDITY_DAYS} days'}), 400
        
        # Create generator
        generator = MLDSACertificateGenerator(security_level, classical_algo)
        
        # Generate in temporary directory
        with tempfile.TemporaryDirectory() as tmpdir:
            # ML-DSA files
            mldsa_key = os.path.join(tmpdir, 'mldsa.key')
            mldsa_pub = os.path.join(tmpdir, 'mldsa.pub')
            
            # Classical files
            classical_key = os.path.join(tmpdir, f'{classical_algo}.key')
            classical_pub = os.path.join(tmpdir, f'{classical_algo}.pub')
            
            # Certificate files
            cert_file = os.path.join(tmpdir, 'cert.crt')
            
            # Generate ML-DSA keys
            if not generator.generate_private_key(mldsa_key):
                return jsonify({'error': 'Failed to generate ML-DSA private key'}), 500
            
            if not generator.generate_public_key(mldsa_key, mldsa_pub):
                return jsonify({'error': 'Failed to generate ML-DSA public key'}), 500
            
            # Generate classical keys
            if not generator.generate_classical_key(classical_key, classical_algo):
                return jsonify({'error': f'Failed to generate {classical_algo.upper()} key'}), 500
            
            if not generator.generate_public_key(classical_key, classical_pub):
                return jsonify({'error': f'Failed to generate {classical_algo.upper()} public key'}), 500
            
            # Generate hybrid certificate
            if not generator.generate_hybrid_certificate(
                mldsa_key, classical_key, cert_file, subject, days, san_list, is_ca
            ):
                return jsonify({'error': 'Failed to generate hybrid certificate'}), 500
            
            # Read all files
            with open(mldsa_key, 'rb') as f:
                mldsa_private_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(mldsa_pub, 'rb') as f:
                mldsa_public_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(classical_key, 'rb') as f:
                classical_private_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(classical_pub, 'rb') as f:
                classical_public_key = base64.b64encode(f.read()).decode('utf-8')
            
            with open(cert_file, 'rb') as f:
                ml_dsa_cert = base64.b64encode(f.read()).decode('utf-8')
            
            # Classical cert
            classical_cert_file = cert_file.replace('.crt', '_classical.crt')
            with open(classical_cert_file, 'rb') as f:
                classical_cert = base64.b64encode(f.read()).decode('utf-8')
        
        return jsonify({
            'ml_dsa_certificate': ml_dsa_cert,
            'classical_certificate': classical_cert,
            'ml_dsa_private_key': mldsa_private_key,
            'ml_dsa_public_key': mldsa_public_key,
            'classical_private_key': classical_private_key,
            'classical_public_key': classical_public_key,
            'security_level': security_level,
            'classical_algorithm': classical_algo,
            'subject': subject,
            'validity_days': days
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


def find_free_port(start_port=5000, max_port=5100):
    """Find an available port to bind to."""
    import socket
    
    for port in range(start_port, max_port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('', port))
            sock.close()
            return port
        except OSError:
            continue
    
    raise RuntimeError(f"No free ports found between {start_port} and {max_port}")


if __name__ == '__main__':
    # Find an available port
    port = find_free_port()
    
    print("=" * 70)
    print("ML-DSA Certificate REST API")
    print("=" * 70)
    print("\nEndpoints:")
    print("  GET  /health                          - Health check")
    print("  GET  /api/v1/info                     - API information")
    print("  POST /api/v1/keys/generate            - Generate key pair")
    print("  POST /api/v1/certificate/generate     - Generate certificate")
    print("  POST /api/v1/csr/generate             - Generate CSR")
    print("  POST /api/v1/certificate/hybrid       - Generate hybrid certificate")
    print(f"\nStarting server on http://localhost:{port}")
    
    if DEBUG_MODE:
        print("\n⚠️  WARNING: Debug mode is enabled. DO NOT use in production!")
    
    print("=" * 70)
    print()
    
    # Debug mode controlled by environment variable
    # Set FLASK_DEBUG=False in production
    app.run(host='0.0.0.0', port=port, debug=DEBUG_MODE)
