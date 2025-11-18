# CSR Signing Feature - Complete Integration

## Overview

The ML-DSA Certificate Generator now supports **signing Certificate Signing Requests (CSRs) with CA certificates** in both the CLI and GUI interfaces.

## ✅ What's Integrated

### 1. Core Library (`mldsa_cert.py`)
- ✅ New method: `sign_csr_with_ca()`
- ✅ Signs CSRs with CA certificates
- ✅ Supports configurable validity periods
- ✅ Option to sign as CA certificate (intermediate CAs)
- ✅ Proper X.509v3 extensions

### 2. Command-Line Interface (CLI)
- ✅ New argument: `--sign-csr CSR_FILE`
- ✅ Required arguments: `--ca-cert` and `--ca-key`
- ✅ Optional arguments: `--days`, `--ca`, `--verify`
- ✅ Input validation and error handling
- ✅ File existence checks
- ✅ Updated help text with examples

### 3. Graphical User Interface (GUI)
- ✅ New tab: "Sign CSR with CA"
- ✅ File browsers for CSR, CA cert, and CA key
- ✅ Configurable signing options
- ✅ Real-time console output
- ✅ Threaded operations (non-blocking UI)
- ✅ Comprehensive validation

## 🚀 Usage Examples

### CLI Usage

#### Complete Workflow
```bash
# Step 1: Generate a CA certificate
python3 mldsa_cert.py \
  --subject "/CN=My Root CA/O=Example Inc/C=US" \
  --ca \
  --days 3650 \
  --output ca

# Step 2: Generate a CSR
python3 mldsa_cert.py \
  --subject "/CN=server.example.com/O=Example Inc" \
  --san "DNS:www.example.com" \
  --csr \
  --output server

# Step 3: Sign the CSR with the CA
python3 mldsa_cert.py \
  --sign-csr server.csr \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --output server-signed \
  --days 365
```

#### With Verification
```bash
python3 mldsa_cert.py \
  --sign-csr server.csr \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --output server-signed \
  --days 365 \
  --verify
```

#### Sign as Intermediate CA
```bash
python3 mldsa_cert.py \
  --sign-csr intermediate.csr \
  --ca-cert rootca.crt \
  --ca-key rootca.key \
  --output intermediate-ca \
  --days 1825 \
  --ca
```

### GUI Usage

1. **Launch GUI**: `./launch-gui.sh` or `python3 gui.py`
2. **Click** "Sign CSR with CA" tab
3. **Browse** and select:
   - CSR file to sign
   - CA certificate
   - CA private key
4. **Configure**:
   - Validity period (days)
   - Output filename
   - CA certificate option (if needed)
5. **Click** "Sign CSR"
6. **View** real-time output in Console tab

## 📋 New CLI Arguments

```
--sign-csr CSR_FILE   Sign a CSR with a CA certificate
--ca-cert CA_CERT     CA certificate file for signing CSRs
--ca-key CA_KEY       CA private key file for signing CSRs
```

**Notes:**
- `--subject` is **not required** when using `--sign-csr`
- `--ca-cert` and `--ca-key` are **required** with `--sign-csr`
- `--output` is still required (for the signed certificate)
- `--days` defaults to 365 days
- `--ca` makes the signed cert a CA certificate

## 🔧 Technical Details

### Method Signature
```python
def sign_csr_with_ca(
    self,
    csr_file: str,          # Path to CSR file
    ca_cert_file: str,      # Path to CA certificate
    ca_key_file: str,       # Path to CA private key
    output_file: str,       # Output certificate path
    days: int = 365,        # Validity period
    is_ca: bool = False     # Sign as CA cert?
) -> bool
```

### OpenSSL Command
```bash
openssl x509 -req \
  -in <csr_file> \
  -CA <ca_cert> \
  -CAkey <ca_key> \
  -CAcreateserial \
  -out <output> \
  -days <validity> \
  -extfile <config> \
  -extensions <v3_ca|v3_end>
```

## 📖 Documentation Updates

- ✅ **README.md**: Added CLI example for CSR signing
- ✅ **GUI-README.md**: Added CSR signing workflow
- ✅ **QUICKSTART-GUI.md**: Added complete workflow example
- ✅ **example-ca-signing.sh**: End-to-end demonstration script
- ✅ CLI help text updated with examples

## 🎯 Use Cases

1. **Internal PKI**: Build your own certificate authority
2. **Development**: Issue development certificates locally
3. **Testing**: Test certificate chains without external CAs
4. **Learning**: Understand PKI workflows hands-on
5. **Intermediate CAs**: Create certificate hierarchies
6. **Microservices**: Issue service-specific certificates

## ✨ Features

### Input Validation
- ✅ File existence checks
- ✅ Required argument validation
- ✅ Clear error messages
- ✅ Helpful guidance

### Error Handling
- ✅ OpenSSL error capture
- ✅ Exception handling
- ✅ User-friendly messages
- ✅ Exit codes for scripting

### Output
- ✅ Progress indicators
- ✅ Success/failure messages
- ✅ File paths displayed
- ✅ Certificate details (with --verify)

## 🧪 Testing

### Quick Test
```bash
# Run the complete workflow example
./example-ca-signing.sh

# This will:
# 1. Generate a CA certificate
# 2. Generate a CSR
# 3. Sign the CSR
# 4. Verify the signed certificate
```

### Manual Test
```bash
# Generate CA
python3 mldsa_cert.py --subject "/CN=Test CA" --ca --output testca

# Generate CSR
python3 mldsa_cert.py --subject "/CN=Test Server" --csr --output testserver

# Sign CSR
python3 mldsa_cert.py --sign-csr testserver.csr --ca-cert testca.crt --ca-key testca.key --output testsigned

# Verify
openssl x509 -in testsigned.crt -text -noout
openssl verify -CAfile testca.crt testsigned.crt
```

## 📦 Files Modified

### Core
- `mldsa_cert.py` - Added `sign_csr_with_ca()` method and CLI support

### GUI
- `gui.py` - Added "Sign CSR with CA" tab (18KB → 29KB)

### Documentation
- `README.md` - Updated with CLI examples
- `GUI-README.md` - Added CSR signing workflow
- `QUICKSTART-GUI.md` - Added workflow examples

### Examples
- `example-ca-signing.sh` - Complete demonstration script (new)

## 🎉 Summary

CSR signing is now **fully integrated** across all interfaces:

| Feature | CLI | GUI | API |
|---------|-----|-----|-----|
| Generate certificates | ✅ | ✅ | ✅ |
| Generate CSRs | ✅ | ✅ | ✅ |
| **Sign CSRs with CA** | ✅ | ✅ | ✅ |
| CA certificates | ✅ | ✅ | ✅ |
| Subject Alt Names | ✅ | ✅ | ✅ |
| Certificate verification | ✅ | ✅ | - |

All workflows are documented with examples and ready for production use!
