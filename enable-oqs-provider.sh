#!/bin/bash
# Enable oqs-provider in OpenSSL configuration

set -e

OPENSSL_ROOT="/usr/local/opt/openssl@3"
OPENSSL_CNF="$OPENSSL_ROOT/etc/openssl@3/openssl.cnf"

echo "Enabling oqs-provider in OpenSSL configuration..."
echo "Config file: $OPENSSL_CNF"
echo ""

# Check if oqsprovider is already configured
if grep -q "oqsprovider" "$OPENSSL_CNF" 2>/dev/null; then
    echo "✓ oqs-provider is already configured in $OPENSSL_CNF"
else
    echo "Adding oqs-provider configuration..."
    
    # Backup the original config
    sudo cp "$OPENSSL_CNF" "$OPENSSL_CNF.backup"
    echo "✓ Backup created: $OPENSSL_CNF.backup"
    
    # Add oqsprovider to the provider_sect section
    sudo sed -i '' '/\[provider_sect\]/a\
oqsprovider = oqsprovider_sect
' "$OPENSSL_CNF"
    
    # Add the oqsprovider configuration section at the end
    sudo tee -a "$OPENSSL_CNF" > /dev/null << 'EOF'

# OQS Provider for post-quantum cryptography
[oqsprovider_sect]
activate = 1
EOF
    
    echo "✓ oqs-provider configuration added"
fi

echo ""
echo "Verifying configuration..."
export PATH="$OPENSSL_ROOT/bin:$PATH"

if openssl list -providers | grep -q "oqsprovider"; then
    echo ""
    echo "======================================================================"
    echo "✓ SUCCESS! OQS Provider is now active"
    echo "======================================================================"
    openssl list -providers
    echo ""
    echo "You can now generate ML-DSA certificates!"
else
    echo ""
    echo "⚠ Warning: Provider not showing up. Trying alternative method..."
    echo ""
    echo "Creating local openssl.cnf in current directory..."
    
    cat > openssl-oqs.cnf << 'EOFLOCAL'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
EOFLOCAL
    
    echo "✓ Created openssl-oqs.cnf"
    echo ""
    echo "Use this command to test with the local config:"
    echo ""
    echo "  OPENSSL_CONF=./openssl-oqs.cnf openssl list -providers"
    echo ""
fi
