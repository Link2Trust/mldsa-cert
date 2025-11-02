#!/bin/bash
# Install OpenSSL 3, liboqs, and oqs-provider on macOS

set -e

echo "======================================================================"
echo "Installing ML-DSA/Post-Quantum Crypto Support for OpenSSL"
echo "======================================================================"
echo ""

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Error: Homebrew is not installed. Install it from https://brew.sh"
    exit 1
fi

# Install OpenSSL 3 and dependencies
echo "Step 1: Installing OpenSSL 3 and build dependencies..."
brew install openssl@3 cmake ninja

# Install liboqs
echo ""
echo "Step 2: Installing liboqs..."
brew install liboqs

# Build and install oqs-provider
echo ""
echo "Step 3: Building and installing oqs-provider from source..."

# Create temporary build directory
BUILD_DIR=$(mktemp -d)
cd "$BUILD_DIR"

echo "Cloning oqs-provider..."
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider

# Get OpenSSL path from Homebrew
OPENSSL_ROOT=$(brew --prefix openssl@3)
LIBOQS_ROOT=$(brew --prefix liboqs)

echo "Building with:"
echo "  OpenSSL: $OPENSSL_ROOT"
echo "  liboqs:  $LIBOQS_ROOT"

# Configure and build
cmake -S . -B _build \
    -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" \
    -Dliboqs_DIR="$LIBOQS_ROOT" \
    -DCMAKE_BUILD_TYPE=Release \
    -GNinja

cmake --build _build

# Install (may require sudo)
echo ""
echo "Installing oqs-provider (may require password)..."
sudo cmake --install _build

# Check installation
MODULES_DIR="$OPENSSL_ROOT/lib/ossl-modules"
echo ""
echo "Checking installation..."
if [ -f "$MODULES_DIR/oqsprovider.dylib" ] || [ -f "$MODULES_DIR/oqsprovider.so" ]; then
    echo "✓ oqs-provider installed successfully!"
else
    # Try alternative location
    if [ -f "/usr/local/lib/ossl-modules/oqsprovider.dylib" ]; then
        echo "✓ oqs-provider installed to /usr/local/lib/ossl-modules/"
    else
        echo "⚠ Warning: Could not verify oqs-provider installation"
    fi
fi

# Clean up
cd ~
rm -rf "$BUILD_DIR"

echo ""
echo "======================================================================"
echo "Installation Complete!"
echo "======================================================================"
echo ""
echo "Add this to your ~/.zshrc to use OpenSSL 3 by default:"
echo ""
echo "  export PATH=\"$OPENSSL_ROOT/bin:\$PATH\""
echo ""
echo "Or run it now:"
echo ""
echo "  export PATH=\"$OPENSSL_ROOT/bin:\$PATH\""
echo ""
echo "Verify the installation with:"
echo ""
echo "  openssl list -providers"
echo ""
echo "You should see 'OpenSSL OQS Provider' in the output."
echo ""
