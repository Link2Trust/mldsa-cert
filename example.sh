#!/bin/bash
# Example usage script for ML-DSA Certificate Generator

set -e

echo "======================================================================"
echo "ML-DSA Certificate Generator - Examples"
echo "======================================================================"
echo ""

# Example 1: Simple self-signed certificate
echo "Example 1: Generating a simple self-signed certificate..."
python3 mldsa_cert.py \
  --subject "/CN=demo.example.com/O=Demo Organization/C=US" \
  --output demo \
  --verify

echo ""
echo "----------------------------------------------------------------------"
echo ""

# Example 2: CA certificate with highest security
echo "Example 2: Generating a Root CA certificate with ML-DSA-87..."
python3 mldsa_cert.py \
  --level ml-dsa-87 \
  --subject "/CN=Demo Root CA/O=Demo CA Inc/C=US" \
  --ca \
  --days 3650 \
  --output demo-ca \
  --verify

echo ""
echo "----------------------------------------------------------------------"
echo ""

# Example 3: Server certificate with SANs
echo "Example 3: Generating a server certificate with multiple SANs..."
python3 mldsa_cert.py \
  --subject "/CN=web.example.com/O=Web Services/C=US" \
  --san "DNS:www.example.com" \
  --san "DNS:example.com" \
  --san "DNS:api.example.com" \
  --san "IP:192.168.1.100" \
  --output webserver \
  --verify

echo ""
echo "----------------------------------------------------------------------"
echo ""

# Example 4: Just generate a key pair
echo "Example 4: Generating only a key pair..."
python3 mldsa_cert.py \
  --level ml-dsa-44 \
  --subject "/CN=test" \
  --key-only \
  --output testkey

echo ""
echo "======================================================================"
echo "All examples completed successfully!"
echo "======================================================================"
echo ""
echo "Generated files:"
ls -lh demo.* demo-ca.* webserver.* testkey.* 2>/dev/null || true
echo ""
