#!/bin/bash
# Example: Complete CA Workflow - Generate CA, CSR, and Sign CSR
# Demonstrates the new CSR signing functionality

set -e

echo "========================================================================"
echo "ML-DSA Certificate Authority Workflow Example"
echo "========================================================================"
echo ""

# Step 1: Generate a CA certificate
echo "Step 1: Generating CA certificate..."
python3 mldsa_cert.py \
  --level ml-dsa-65 \
  --subject "/CN=Example Root CA/O=Example Inc/C=US" \
  --ca \
  --days 3650 \
  --output example-ca

echo ""
echo "✓ CA certificate generated:"
echo "  - example-ca.key (CA private key - keep secure!)"
echo "  - example-ca.pub (CA public key)"
echo "  - example-ca.crt (CA certificate)"
echo ""

# Step 2: Generate a CSR for a server certificate
echo "Step 2: Generating CSR for server certificate..."
python3 mldsa_cert.py \
  --subject "/CN=server.example.com/O=Example Inc/C=US" \
  --san "DNS:www.example.com" \
  --san "DNS:example.com" \
  --csr \
  --output server

echo ""
echo "✓ CSR generated:"
echo "  - server.key (Server private key)"
echo "  - server.pub (Server public key)"
echo "  - server.csr (Certificate Signing Request)"
echo ""

# Step 3: Sign the CSR with the CA
echo "Step 3: Signing CSR with CA certificate..."
python3 -c "
from mldsa_cert import MLDSACertificateGenerator

# Create generator instance
gen = MLDSACertificateGenerator('ml-dsa-65')

# Sign the CSR
success = gen.sign_csr_with_ca(
    csr_file='server.csr',
    ca_cert_file='example-ca.crt',
    ca_key_file='example-ca.key',
    output_file='server-signed.crt',
    days=365,
    is_ca=False
)

if success:
    print('')
    print('✓ CSR signed successfully!')
else:
    print('')
    print('✗ Failed to sign CSR')
    exit(1)
"

echo ""
echo "✓ Server certificate signed:"
echo "  - server-signed.crt (CA-signed server certificate)"
echo ""

# Step 4: Verify the signed certificate
echo "Step 4: Verifying the signed certificate..."
echo "------------------------------------------------------------------------"
/usr/local/opt/openssl@3/bin/openssl x509 -in server-signed.crt -text -noout | head -30

echo ""
echo "========================================================================"
echo "Workflow Complete!"
echo "========================================================================"
echo ""
echo "You now have:"
echo "  1. A CA certificate (example-ca.crt) that can sign other certificates"
echo "  2. A server CSR (server.csr) with the requested subject and SANs"
echo "  3. A CA-signed server certificate (server-signed.crt)"
echo ""
echo "To use in the GUI:"
echo "  1. Generate CA: Use 'Certificate Generation' tab with CA checkbox"
echo "  2. Generate CSR: Use 'Certificate Generation' tab with CSR checkbox"
echo "  3. Sign CSR: Use 'Sign CSR with CA' tab to create signed certificate"
echo ""
echo "Clean up test files:"
echo "  rm -f example-ca.* server.* server-signed.crt"
echo ""
