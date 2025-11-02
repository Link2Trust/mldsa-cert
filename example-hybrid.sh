#!/bin/bash
# Example script for generating hybrid ML-DSA certificates

set -e

echo "======================================================================"
echo "ML-DSA Hybrid Certificate Generator - Examples"
echo "======================================================================"
echo ""

# Example 1: Hybrid certificate with RSA
echo "Example 1: Generating hybrid certificate (ML-DSA-65 + RSA-3072)..."
python3 mldsa_cert.py \
  --subject "/CN=web.example.com/O=Example Corp/C=US" \
  --hybrid rsa \
  --san "DNS:www.example.com" \
  --san "DNS:example.com" \
  --output hybrid-rsa \
  --verify

echo ""
echo "----------------------------------------------------------------------"
echo ""

# Example 2: Hybrid certificate with ECDSA
echo "Example 2: Generating hybrid certificate (ML-DSA-65 + ECDSA P-384)..."
python3 mldsa_cert.py \
  --subject "/CN=api.example.com/O=Example Corp/C=US" \
  --hybrid ecdsa \
  --san "DNS:api.example.com" \
  --output hybrid-ecdsa \
  --verify

echo ""
echo "----------------------------------------------------------------------"
echo ""

# Example 3: High-security hybrid CA
echo "Example 3: Generating high-security hybrid CA (ML-DSA-87 + RSA)..."
python3 mldsa_cert.py \
  --level ml-dsa-87 \
  --subject "/CN=Hybrid Root CA/O=Example CA/C=US" \
  --hybrid rsa \
  --ca \
  --days 3650 \
  --output hybrid-ca \
  --verify

echo ""
echo "======================================================================"
echo "All hybrid certificate examples completed!"
echo "======================================================================"
echo ""
echo "Generated files:"
echo ""
echo "Example 1 (RSA):"
ls -lh hybrid-rsa* 2>/dev/null || true
echo ""
echo "Example 2 (ECDSA):"
ls -lh hybrid-ecdsa* 2>/dev/null || true
echo ""
echo "Example 3 (CA):"
ls -lh hybrid-ca* 2>/dev/null || true
echo ""

echo "======================================================================"
echo "Comparing Certificate Algorithms"
echo "======================================================================"
echo ""

echo "ML-DSA Certificate:"
/usr/local/opt/openssl@3/bin/openssl x509 -in hybrid-rsa.crt -noout -text | grep "Signature Algorithm"
echo ""

echo "Classical RSA Certificate:"
/usr/local/opt/openssl@3/bin/openssl x509 -in hybrid-rsa_classical.crt -noout -text | grep "Signature Algorithm"
echo ""

echo "======================================================================"
echo "File Size Comparison"
echo "======================================================================"
echo ""
echo "ML-DSA certificates are larger due to post-quantum signatures:"
echo ""
du -h hybrid-rsa.crt hybrid-rsa_classical.crt
echo ""
