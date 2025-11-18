# ML-DSA Certificate Generator

Generate X.509 certificates using **ML-DSA** (Module-Lattice-Based Digital Signature Algorithm) according to **RFC 9881** specifications.

ML-DSA is a NIST-selected post-quantum cryptographic signature algorithm, formerly known as CRYSTALS-Dilithium. This tool enables you to generate quantum-resistant certificates for future-proof security.

## Features

- ✅ RFC 9881 compliant ML-DSA certificate generation
- ✅ Support for all three ML-DSA security levels (44, 65, 87)
- ✅ Self-signed certificate generation
- ✅ Certificate Signing Request (CSR) generation
- ✅ CA certificate generation
- ✅ Subject Alternative Names (SAN) support
- ✅ Certificate verification and inspection
- ✅ Key pair generation
- ✅ **Graphical User Interface (GUI)** - Easy-to-use desktop application
- ✅ **REST API** - HTTP API for remote certificate generation

## Security Levels

ML-DSA offers three security levels corresponding to different NIST security categories:

| Level | NIST Security | Equivalent Classical | Use Case |
|-------|---------------|---------------------|----------|
| **ML-DSA-44** | Level 2 | AES-128 | Standard security applications |
| **ML-DSA-65** | Level 3 | AES-192 | **Recommended default** |
| **ML-DSA-87** | Level 5 | AES-256 | High security requirements |

## Requirements

### System Requirements

- **Python 3.7+** (uses only standard library)
- **OpenSSL 3.0+** with OQS provider support
- **liboqs** - Open Quantum Safe cryptographic library
- **oqs-provider** - OpenSSL 3 provider for post-quantum algorithms

## Installation

### macOS

#### Quick Install (Recommended)

Use the provided installation script:

```bash
./install-oqs.sh
```

This will:
1. Install OpenSSL 3 and liboqs via Homebrew
2. Build and install oqs-provider from source
3. Configure everything automatically

#### Manual Installation

```bash
# Install dependencies via Homebrew
brew install openssl@3 liboqs cmake ninja

# Build oqs-provider from source (not available in Homebrew)
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider

# Configure build
cmake -S . -B _build \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3) \
  -Dliboqs_DIR=$(brew --prefix liboqs) \
  -DCMAKE_BUILD_TYPE=Release \
  -GNinja

# Build and install
cmake --build _build
sudo cmake --install _build
```

#### Post-Installation (macOS)

The application automatically uses the correct OpenSSL binary and configuration. The `openssl-oqs.cnf` file in the project directory enables the OQS provider.

**No PATH modifications needed!** The app is pre-configured to use `/usr/local/opt/openssl@3/bin/openssl`.

### Linux (Ubuntu/Debian)

#### Install Dependencies

```bash
sudo apt update
sudo apt install -y build-essential git cmake ninja-build \
  libssl-dev python3 openssl
```

#### Install OpenSSL 3.0+ (if needed)

Ubuntu 22.04+ includes OpenSSL 3 by default. For older versions:

```bash
# Check OpenSSL version
openssl version

# If < 3.0, build from source:
wget https://www.openssl.org/source/openssl-3.6.0.tar.gz
tar -xzf openssl-3.6.0.tar.gz
cd openssl-3.6.0
./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
make -j$(nproc)
sudo make install

# Update library path
sudo ldconfig /usr/local/ssl/lib
```

#### Build and Install liboqs

```bash
git clone -b main https://github.com/open-quantum-safe/liboqs.git
cd liboqs
cmake -S . -B build \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_INSTALL_PREFIX=/usr/local \
  -GNinja
cmake --build build
sudo cmake --install build
cd ..
```

#### Build and Install oqs-provider

```bash
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
cmake -S . -B _build \
  -DOPENSSL_ROOT_DIR=/usr/local/ssl \
  -DCMAKE_PREFIX_PATH=/usr/local \
  -GNinja
cmake --build _build
sudo cmake --install _build
```

#### Configure for Linux

Update the `mldsa_cert.py` script to use the correct OpenSSL path:

```bash
# Edit line 21 in mldsa_cert.py to use your OpenSSL 3 path
# For system OpenSSL 3:
OPENSSL_BIN = '/usr/bin/openssl'

# Or for custom built OpenSSL:
OPENSSL_BIN = '/usr/local/ssl/bin/openssl'
```

### Windows

#### Prerequisites

1. **Install Python 3.7+**: Download from [python.org](https://www.python.org/downloads/)
2. **Install Visual Studio Build Tools**: Required for compiling
   - Download from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/downloads/)
   - Select "Desktop development with C++"

#### Install vcpkg (Package Manager)

```powershell
# Open PowerShell as Administrator
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
```

#### Install OpenSSL 3 via vcpkg

```powershell
cd C:\vcpkg
.\vcpkg install openssl:x64-windows
```

#### Build liboqs

```powershell
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build
cd build

cmake -GNinja .. `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DCMAKE_BUILD_TYPE=Release `
  -DBUILD_SHARED_LIBS=ON

cmake --build .
cmake --install .
```

#### Build oqs-provider

```powershell
git clone https://github.com/open-quantum-safe/oqs-provider.git
cd oqs-provider
mkdir _build
cd _build

cmake -GNinja .. `
  -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DCMAKE_BUILD_TYPE=Release

cmake --build .
cmake --install .
```

#### Configure for Windows

Update `mldsa_cert.py` for Windows:

```python
# Line 21 - Update OpenSSL binary path
OPENSSL_BIN = r'C:\vcpkg\installed\x64-windows\tools\openssl\openssl.exe'

# Or if OpenSSL is in PATH:
OPENSSL_BIN = 'openssl.exe'
```

### Verify Installation (All Platforms)

Check that the OQS provider is available:

```bash
# macOS/Linux
/usr/local/opt/openssl@3/bin/openssl list -providers  # macOS
openssl list -providers  # Linux

# Windows (PowerShell)
openssl.exe list -providers
```

Expected output:
```
Providers:
  default
    name: OpenSSL Default Provider
    version: 3.6.0
    status: active
  oqsprovider
    name: OpenSSL OQS Provider
    version: 0.10.1-dev
    status: active
```

### Quick Test

```bash
# Test certificate generation
python3 mldsa_cert.py --subject "/CN=test.example.com" --output test

# Windows
python mldsa_cert.py --subject "/CN=test.example.com" --output test
```

## Usage

### Using the GUI (Recommended for Beginners)

Launch the graphical interface:

```bash
python3 gui.py
# or
./gui.py
```

The GUI provides:
- Visual interface for all certificate options
- Real-time console output
- Built-in certificate verification
- Subject Alternative Name (SAN) management
- **Sign CSRs with your CA certificate** (new!)
- No command-line knowledge required

**See [GUI-README.md](GUI-README.md) for detailed GUI documentation.**

### Using the Command Line

#### Basic Examples

#### 1. Generate a Self-Signed Certificate (Default ML-DSA-65)

```bash
python3 mldsa_cert.py \
  --subject "/CN=example.com/O=Example Org/C=US" \
  --output mycert
```

This creates:
- `mycert.key` - Private key
- `mycert.pub` - Public key  
- `mycert.crt` - Certificate

#### 2. Generate a CA Certificate with Highest Security

```bash
python3 mldsa_cert.py \
  --level ml-dsa-87 \
  --subject "/CN=My Root CA/O=Example Inc/C=US" \
  --ca \
  --days 3650 \
  --output ca
```

#### 3. Generate Certificate with Subject Alternative Names

```bash
python3 mldsa_cert.py \
  --subject "/CN=web.example.com/O=Example Corp" \
  --san "DNS:www.example.com" \
  --san "DNS:example.com" \
  --san "DNS:api.example.com" \
  --output webserver
```

#### 4. Generate a Certificate Signing Request (CSR)

```bash
python3 mldsa_cert.py \
  --subject "/CN=app.example.com/O=Example Ltd" \
  --csr \
  --output app
```

Creates `app.key`, `app.pub`, and `app.csr`

#### 5. Generate Only a Key Pair

```bash
python3 mldsa_cert.py \
  --subject "/CN=test" \
  --key-only \
  --output testkey
```

#### 6. Sign a CSR with a CA Certificate

```bash
# First, generate a CA
python3 mldsa_cert.py \
  --subject "/CN=My Root CA/O=Example Inc/C=US" \
  --ca \
  --days 3650 \
  --output ca

# Then, generate a CSR
python3 mldsa_cert.py \
  --subject "/CN=server.example.com/O=Example Inc" \
  --csr \
  --output server

# Finally, sign the CSR with the CA
python3 mldsa_cert.py \
  --sign-csr server.csr \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --output server-signed \
  --days 365
```

Creates `server-signed.crt` - CA-signed certificate

#### 7. Verify Certificate After Generation

```bash
python3 mldsa_cert.py \
  --subject "/CN=test.example.com" \
  --verify \
  --output test
```

### Command-Line Options

```
usage: mldsa_cert.py [-h] [--level {ml-dsa-44,ml-dsa-65,ml-dsa-87}]
                     [--subject SUBJECT] [--output OUTPUT] [--days DAYS]
                     [--san SAN] [--ca] [--csr] [--key-only] [--verify]
                     [--sign-csr CSR_FILE] [--ca-cert CA_CERT] [--ca-key CA_KEY]

Generate ML-DSA (Post-Quantum) X.509 Certificates (RFC 9881)

options:
  -h, --help            show this help message and exit
  --level {ml-dsa-44,ml-dsa-65,ml-dsa-87}
                        ML-DSA security level (default: ml-dsa-65)
  --subject SUBJECT     Certificate subject (required unless using --sign-csr)
  --output OUTPUT       Output file prefix (will create .key, .pub, .crt files)
  --days DAYS           Certificate validity period in days (default: 365)
  --san SAN             Subject Alternative Name (can be specified multiple times)
  --ca                  Generate a CA certificate
  --csr                 Generate a CSR instead of self-signed certificate
  --key-only            Generate only the key pair (no certificate)
  --verify              Verify and display certificate details after generation
  --sign-csr CSR_FILE   Sign a CSR with a CA certificate (requires --ca-cert and --ca-key)
  --ca-cert CA_CERT     CA certificate file for signing CSRs
  --ca-key CA_KEY       CA private key file for signing CSRs
```

## RFC 9881 Compliance

This tool implements ML-DSA certificates according to [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881.html), which defines:

### ML-DSA Algorithm Object Identifiers

The following OIDs are used as specified in RFC 9881:

```
id-ml-dsa-44 OBJECT IDENTIFIER ::= { id-nist-sha3 17 }  # 2.16.840.1.101.3.4.3.17
id-ml-dsa-65 OBJECT IDENTIFIER ::= { id-nist-sha3 18 }  # 2.16.840.1.101.3.4.3.18
id-ml-dsa-87 OBJECT IDENTIFIER ::= { id-nist-sha3 19 }  # 2.16.840.1.101.3.4.3.19
```

### Certificate Extensions

Generated certificates include proper X.509v3 extensions:

- **Basic Constraints**: Critical, CA:TRUE/FALSE
- **Key Usage**: Critical, digitalSignature, keyCertSign (for CA)
- **Subject Key Identifier**: Hash of public key
- **Authority Key Identifier**: Issuer's public key hash
- **Subject Alternative Names**: DNS names, IP addresses (optional)

## Inspecting Generated Certificates

### View Certificate Details

```bash
openssl x509 -in mycert.crt -text -noout
```

### View Private Key

```bash
openssl pkey -in mycert.key -text -noout
```

### View Public Key

```bash
openssl pkey -in mycert.pub -pubin -text -noout
```

### Verify Certificate Signature

```bash
openssl verify -CAfile ca.crt mycert.crt
```

## Example: Creating a Certificate Chain

### 1. Create Root CA

```bash
python3 mldsa_cert.py \
  --level ml-dsa-87 \
  --subject "/CN=Root CA/O=Example Corp/C=US" \
  --ca \
  --days 7300 \
  --output root-ca
```

### 2. Create Intermediate CA CSR

```bash
python3 mldsa_cert.py \
  --level ml-dsa-65 \
  --subject "/CN=Intermediate CA/O=Example Corp/C=US" \
  --csr \
  --output intermediate-ca
```

### 3. Sign Intermediate with Root (Manual)

```bash
openssl x509 -req \
  -in intermediate-ca.csr \
  -CA root-ca.crt \
  -CAkey root-ca.key \
  -CAcreateserial \
  -out intermediate-ca.crt \
  -days 3650 \
  -extensions v3_ca
```

### 4. Create End-Entity Certificate

```bash
python3 mldsa_cert.py \
  --subject "/CN=server.example.com/O=Example Corp" \
  --san "DNS:www.example.com" \
  --san "DNS:example.com" \
  --output server
```

## Troubleshooting

### Error: "OpenSSL does not appear to support ML-DSA"

**Solution**: Install oqs-provider as described in the Requirements section.

### Error: "algorithm not found"

**Solution**: Make sure oqs-provider is properly installed and configured:

```bash
# Check provider location
ls /opt/homebrew/lib/ossl-modules/  # macOS
ls /usr/local/lib/ossl-modules/     # Linux

# Should contain: oqsprovider.so or oqsprovider.dylib
```

### LibreSSL vs OpenSSL

macOS ships with LibreSSL by default, which doesn't support oqs-provider. You must use OpenSSL 3.0+:

```bash
# Use Homebrew OpenSSL explicitly
export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"

# Or create an alias
alias openssl="/opt/homebrew/opt/openssl@3/bin/openssl"
```

## Security Considerations

1. **Private Key Protection**: Store private keys securely with appropriate file permissions:
   ```bash
   chmod 600 *.key
   ```

2. **Key Backup**: ML-DSA keys are larger than traditional RSA/ECDSA keys. Ensure adequate storage for backups.

3. **Certificate Lifetime**: Post-quantum certificates may have different lifetime considerations. RFC 9881 doesn't mandate specific lifetimes.

## Key and Signature Sizes

ML-DSA has different size characteristics compared to classical algorithms:

| Algorithm | Private Key | Public Key | Signature |
|-----------|-------------|------------|-----------|
| ML-DSA-44 | ~2,560 B    | ~1,312 B   | ~2,420 B  |
| ML-DSA-65 | ~4,032 B    | ~1,952 B   | ~3,309 B  |
| ML-DSA-87 | ~4,896 B    | ~2,592 B   | ~4,627 B  |
| RSA-2048  | ~1,192 B    | ~294 B     | ~256 B    |
| ECDSA P-256 | ~32 B     | ~64 B      | ~64 B     |

ML-DSA keys and signatures are significantly larger but provide quantum resistance.

## References

- [RFC 9881 - ML-DSA in X.509 Certificates](https://www.rfc-editor.org/rfc/rfc9881.html)
- [NIST FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [oqs-provider GitHub](https://github.com/open-quantum-safe/oqs-provider)
- [liboqs GitHub](https://github.com/open-quantum-safe/liboqs)

## License

This tool is provided as-is for educational and development purposes. Ensure compliance with your organization's security policies before use in production.

## Contributing

Contributions welcome! Please ensure any changes maintain RFC 9881 compliance.
