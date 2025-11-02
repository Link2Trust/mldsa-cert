# Project Structure

## Files Overview

### Core Application
- **`mldsa_cert.py`** (23 KB) - Main certificate generation application
  - Generates ML-DSA certificates (RFC 9881 compliant)
  - Supports hybrid certificates (ML-DSA + RSA/ECDSA)
  - Full command-line interface
  - Auto-detects OpenSSL 3 with OQS provider

### Configuration
- **`openssl-oqs.cnf`** (203 B) - OpenSSL configuration for OQS provider
  - Enables ML-DSA/Dilithium algorithms
  - Required for post-quantum cryptography support

### Installation Scripts
- **`install-oqs.sh`** (2.6 KB) - Automated installation for macOS
  - Installs OpenSSL 3, liboqs, and oqs-provider
  - Configures everything automatically
  
- **`enable-oqs-provider.sh`** (2.1 KB) - Manual OQS provider configuration
  - Alternative configuration method
  - Creates local OpenSSL config if needed

### Example Scripts
- **`example.sh`** (1.9 KB) - Basic certificate generation examples
  - Self-signed certificates
  - CA certificates
  - SANs (Subject Alternative Names)
  - Key pairs only
  
- **`example-hybrid.sh`** (2.6 KB) - Hybrid certificate examples
  - ML-DSA + RSA combinations
  - ML-DSA + ECDSA combinations
  - High-security CA examples
  - Certificate comparison demos

### Documentation
- **`README.md`** (16 KB) - Main documentation
  - Installation for macOS, Linux, Windows
  - Usage examples
  - RFC 9881 compliance details
  - Troubleshooting guide
  
- **`HYBRID-GUIDE.md`** (8.9 KB) - Hybrid certificate guide
  - Detailed hybrid certificate explanation
  - Algorithm selection guide
  - Deployment strategies
  - Migration timeline
  - Best practices
  
- **`requirements.txt`** (306 B) - Python dependencies
  - Documents that only stdlib is needed
  - Lists system requirements

- **`PROJECT-STRUCTURE.md`** (this file) - Project organization

### Generated Files (Not in repo)
- **`.gitignore`** - Prevents committing generated certificates

When you run the tool, it generates:
- `.key` files - Private keys
- `.pub` files - Public keys
- `.crt` files - Certificates
- `.csr` files - Certificate signing requests
- `_classical.crt` - Classical certificates (hybrid mode)
- `_mldsa.crt` - ML-DSA certificates (hybrid mode)
- `_rsa.key`, `_ecdsa.key` - Classical keys (hybrid mode)

## Usage Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    Installation                              │
└─────────────────────────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
        install-oqs.sh      enable-oqs-provider.sh
                │                     │
                └──────────┬──────────┘
                           ▼
                   OpenSSL 3 + OQS
                           │
┌─────────────────────────────────────────────────────────────┐
│                 Certificate Generation                       │
└─────────────────────────────────────────────────────────────┘
                           │
                ┌──────────┴──────────┐
                ▼                     ▼
          Pure ML-DSA          Hybrid Mode
         mldsa_cert.py      mldsa_cert.py --hybrid
                │                     │
                ▼                     ▼
          ML-DSA cert         ML-DSA + Classical
           (.crt)             (.crt, _classical.crt)
```

## Command Examples

### Quick Start
```bash
# Install dependencies (macOS)
./install-oqs.sh

# Generate standard ML-DSA certificate
python3 mldsa_cert.py --subject "/CN=example.com" --output mycert

# Generate hybrid certificate
python3 mldsa_cert.py --subject "/CN=example.com" --hybrid rsa --output hybrid

# Run examples
./example.sh
./example-hybrid.sh
```

## File Purposes

| File | Purpose | When to Use |
|------|---------|-------------|
| `mldsa_cert.py` | Generate certificates | Always (main tool) |
| `install-oqs.sh` | Setup on macOS | First-time installation |
| `example.sh` | Learn basic usage | Getting started |
| `example-hybrid.sh` | Learn hybrid certs | Transition scenarios |
| `README.md` | Full documentation | Installation & reference |
| `HYBRID-GUIDE.md` | Hybrid deep dive | Planning PQC migration |
| `openssl-oqs.cnf` | OpenSSL config | Auto-used by tool |

## Dependencies

### System Level
- OpenSSL 3.0+
- liboqs (Open Quantum Safe library)
- oqs-provider (OpenSSL provider)
- Python 3.7+

### Python (Standard Library Only)
- subprocess
- os
- sys
- tempfile
- datetime
- pathlib
- typing
- argparse

No external Python packages required!

## Size Summary

| Category | Files | Total Size |
|----------|-------|------------|
| Application | 1 | 23 KB |
| Documentation | 3 | 25.8 KB |
| Scripts | 4 | 9.2 KB |
| Configuration | 2 | 509 B |
| **Total** | **10** | **~58 KB** |

## Development

### Adding New Features

1. **Modify `mldsa_cert.py`**
   - Add methods to `MLDSACertificateGenerator` class
   - Update `main()` for new CLI arguments
   - Update help text and examples

2. **Update Documentation**
   - Add examples to `README.md`
   - Create dedicated guide if feature is complex
   - Update `example.sh` or create new example script

3. **Test**
   - Test on all supported platforms
   - Verify RFC 9881 compliance
   - Check hybrid mode compatibility

### Contributing

- Keep pure Python (stdlib only)
- Follow existing code style
- Maintain RFC 9881 compliance
- Update documentation
- Test hybrid and pure ML-DSA modes

## Platform-Specific Notes

### macOS
- Use Homebrew for dependencies
- LibreSSL is default (not compatible)
- Must use OpenSSL 3 from Homebrew
- Path: `/usr/local/opt/openssl@3/bin/openssl`

### Linux
- Ubuntu 22.04+ has OpenSSL 3
- Older versions need manual build
- Check `README.md` for full instructions

### Windows
- Use vcpkg for dependencies
- Requires Visual Studio Build Tools
- PowerShell commands differ
- Path handling uses backslashes

## Version History

- **v1.0** - Initial ML-DSA certificate support
- **v1.1** - Added hybrid certificate mode (current)
  - RSA-3072 support
  - ECDSA P-384 support
  - Comprehensive hybrid documentation
  - Enhanced examples

## Future Enhancements

Potential features for future versions:
- [ ] True hybrid ASN.1 encoding (single cert with both algorithms)
- [ ] Certificate chain generation
- [ ] OCSP responder support
- [ ] Certificate revocation lists (CRLs)
- [ ] Batch certificate generation
- [ ] Certificate renewal automation
- [ ] Web UI for certificate generation
- [ ] Container/Docker support

## License

See main README.md for license information.
