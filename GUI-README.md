# ML-DSA Certificate Generator GUI

A modern graphical user interface for generating post-quantum X.509 certificates using ML-DSA (Module-Lattice-Based Digital Signature Algorithm).

## Features

- **Intuitive Interface**: Easy-to-use GUI with clear sections for all certificate parameters
- **Security Level Selection**: Choose from ML-DSA-44, ML-DSA-65, or ML-DSA-87
- **Subject Information**: Input Common Name, Organization, Organizational Unit, and Country
- **Subject Alternative Names (SANs)**: Add multiple DNS names and IP addresses
- **Certificate Options**:
  - Set validity period (1-7300 days)
  - Generate CA certificates
  - Generate CSR instead of full certificate
  - Generate key pairs only
- **CSR Signing with CA**: Sign existing CSRs with your CA certificate (new!)
- **Real-time Console Output**: View all generation progress and OpenSSL output
- **Certificate Verification**: Load and verify existing certificates
- **Threaded Operations**: Non-blocking UI during certificate generation

## Requirements

- Python 3.7+
- tkinter (usually included with Python)
- OpenSSL 3.0+ with OQS provider
- liboqs and oqs-provider installed

## Installation

### macOS

1. Install dependencies:
```bash
./install-oqs.sh
```

2. Launch the GUI:
```bash
python3 gui.py
# or
./gui.py
```

### Linux

1. Install OpenSSL 3.0+ with oqs-provider (see main README.md)

2. Launch the GUI:
```bash
python3 gui.py
```

### Windows

1. Install dependencies via vcpkg (see main README.md)

2. Launch the GUI:
```powershell
python gui.py
```

## Usage

### Generating a Basic Certificate

1. **Select Security Level**: Choose ML-DSA-65 (recommended) or another level
2. **Enter Subject Information**:
   - Common Name (CN): Required (e.g., "example.com")
   - Organization (O): Optional (e.g., "Example Inc")
   - Other fields: Optional
3. **Set Certificate Options**:
   - Validity: Default is 365 days
   - Output filename: Choose where to save (without extension)
4. **Click "Generate Certificate"**
5. View progress in the "Output Console" tab

Generated files:
- `certificate.key` - Private key
- `certificate.pub` - Public key
- `certificate.crt` - Certificate

### Generating a CA Certificate

1. Follow basic certificate steps
2. Check **"Generate as CA certificate"**
3. Increase validity period (e.g., 3650 days for 10 years)
4. Click "Generate Certificate"

### Adding Subject Alternative Names (SANs)

1. In the "Subject Alternative Names" section, click **"Add DNS Name"** or **"Add IP Address"**
2. Enter the DNS name (e.g., "www.example.com") or IP address
3. Repeat to add multiple SANs
4. Remove entries by selecting them and clicking **"Remove Selected"**

### Generating a Certificate Signing Request (CSR)

1. Enter subject information
2. Check **"Generate CSR instead of certificate"**
3. Click "Generate Certificate"

Output:
- `certificate.key` - Private key
- `certificate.pub` - Public key
- `certificate.csr` - Certificate Signing Request

### Generating Key Pair Only

1. Enter Common Name (required for subject)
2. Check **"Generate key pair only"**
3. Click "Generate Certificate"

Output:
- `certificate.key` - Private key
- `certificate.pub` - Public key

### Signing a CSR with Your CA (New!)

Use the **"Sign CSR with CA"** tab to sign existing Certificate Signing Requests:

1. Click the **"Sign CSR with CA"** tab
2. **CSR file**: Browse and select the CSR file to sign (e.g., `app.csr`)
3. **CA certificate**: Browse and select your CA certificate (e.g., `rootca.crt`)
4. **CA private key**: Browse and select your CA private key (e.g., `rootca.key`)
5. **Validity**: Set certificate validity period (default 365 days)
6. **Output filename**: Choose output name (e.g., `signed-cert`)
7. (Optional) Check **"Sign as CA certificate"** if the signed cert should be able to sign other certs
8. Click **"Sign CSR"**
9. View progress in Output Console tab

Output:
- `signed-cert.crt` - Signed certificate

**Typical workflow**:
1. Generate a CA certificate (Certificate Generation tab, check "Generate as CA certificate")
2. Generate a CSR (Certificate Generation tab, check "Generate CSR instead of certificate")
3. Sign the CSR with your CA (Sign CSR with CA tab)

### Verifying Certificates

1. Click **"Verify Certificate"**
2. Select a certificate file (.crt or .pem)
3. View certificate details in the Output Console tab

## GUI Layout

### Certificate Generation Tab

- **Security Level**: Radio buttons for ML-DSA-44/65/87
- **Subject Information**: Fields for CN, O, OU, C
- **Subject Alternative Names**: List with add/remove buttons
- **Certificate Options**: Validity, output filename, CA/CSR/key-only checkboxes
- **Action Buttons**: Generate, Verify, Clear Console

### Sign CSR with CA Tab (New!)

- **CSR File Selection**: Browse for CSR file to sign
- **CA Certificate & Key**: Browse for CA certificate and private key
- **Signing Options**: Validity period, output filename, CA certificate option
- **Action Buttons**: Sign CSR, Verify Signed Certificate

### Output Console Tab

- Real-time output from certificate generation and signing
- All print statements and errors appear here
- Automatic scrolling to show latest output

### Status Bar

- Bottom of window
- Shows current operation status
- Updates during generation: "Ready" → "Generating certificate..." → "Certificate generated successfully"

## Keyboard Shortcuts

- **Tab**: Navigate between fields
- **Enter**: Submit current field
- **Space**: Toggle checkboxes

## Troubleshooting

### GUI won't start

**Error**: `ModuleNotFoundError: No module named 'tkinter'`

**Solution**: Install tkinter:
- macOS: `brew install python-tk`
- Ubuntu/Debian: `sudo apt-get install python3-tk`
- Fedora: `sudo dnf install python3-tkinter`

### Certificate generation fails

**Error**: "OpenSSL does not appear to support ML-DSA"

**Solution**: Install OQS provider:
```bash
./install-oqs.sh  # macOS
```

See main README.md for Linux/Windows installation.

### GUI freezes during generation

This should not happen as operations run in a separate thread. If it does:
1. Check the Output Console tab for errors
2. Ensure OpenSSL is properly installed
3. Try generating via CLI to isolate the issue:
```bash
python3 mldsa_cert.py --subject "/CN=test" --output test
```

### Can't see output in console

The console automatically switches to the "Output Console" tab when you click "Generate Certificate". If output is missing:
1. Click the "Output Console" tab
2. Check that stdout/stderr are not redirected by another process

## Example Workflows

### Generate a Web Server Certificate

1. Common Name: "web.example.com"
2. Organization: "Example Inc"
3. Add SANs: "www.example.com", "example.com"
4. Validity: 365 days
5. Output: "webserver"
6. Click Generate

### Generate a Root CA

1. Common Name: "Example Root CA"
2. Organization: "Example Inc"
3. Check "Generate as CA certificate"
4. Validity: 3650 days (10 years)
5. Output: "rootca"
6. Click Generate

### Generate a CSR for External CA

1. Common Name: "app.example.com"
2. Organization: "Example Inc"
3. Check "Generate CSR instead of certificate"
4. Output: "app-csr"
5. Click Generate
6. Send `app-csr.csr` to your CA for signing

## Integration with CLI

The GUI uses the same `MLDSACertificateGenerator` class as the CLI tool (`mldsa_cert.py`), ensuring identical certificate generation behavior.

You can switch between GUI and CLI freely:
```bash
# Generate with GUI
./gui.py

# Verify with CLI
python3 mldsa_cert.py --verify --output certificate
openssl x509 -in certificate.crt -text -noout
```

## Technical Details

- **Framework**: tkinter (Python standard library)
- **Threading**: Separate worker thread for certificate generation to keep UI responsive
- **Output Redirection**: stdout/stderr redirected to console widget
- **File Dialog**: Native OS file picker for output location
- **Validation**: Input validation before generation starts

## Security Notes

- Private keys are generated locally and never transmitted
- Console output does not display private key contents
- Files are saved with standard permissions (read/write for user)
- Consider setting restrictive permissions on private keys:
```bash
chmod 600 certificate.key
```

## Comparison: GUI vs CLI vs API

| Feature | GUI | CLI | REST API |
|---------|-----|-----|----------|
| User-friendly | ✓ | - | - |
| Automation | - | ✓ | ✓ |
| Batch generation | - | ✓ | ✓ |
| Remote access | - | - | ✓ |
| Visual feedback | ✓ | - | - |
| Scripting | - | ✓ | ✓ |

**Use GUI when**: Learning, one-off certificates, visual workflow preferred

**Use CLI when**: Scripting, automation, CI/CD pipelines

**Use API when**: Remote generation, web integration, microservices

## Screenshots

### Certificate Generation Tab
```
┌─────────────────────────────────────────────────────────┐
│ ML-DSA Certificate Generator                            │
│ Post-Quantum X.509 Certificates (RFC 9881)              │
├─────────────────────────────────────────────────────────┤
│ [Certificate Generation] [Output Console]               │
│                                                          │
│ Security Level                                           │
│ ○ ML-DSA-44 (NIST Level 2, ~AES-128)                    │
│ ● ML-DSA-65 (NIST Level 3, ~AES-192) [Recommended]     │
│ ○ ML-DSA-87 (NIST Level 5, ~AES-256)                    │
│                                                          │
│ Subject Information                                      │
│ Common Name (CN):    [example.com____________]          │
│ Organization (O):     [Example Inc___________]          │
│ Organizational Unit: [IT Department_________]           │
│ Country (C):         [US_____________________]          │
│                                                          │
│ Subject Alternative Names (SANs)                         │
│ ┌────────────────────────────────────────┐              │
│ │ DNS:www.example.com                    │              │
│ │ DNS:mail.example.com                   │              │
│ └────────────────────────────────────────┘              │
│ [Add DNS Name] [Add IP Address] [Remove Selected]       │
│                                                          │
│ Certificate Options                                      │
│ Validity (days):  [365▼]                                │
│ Output filename:  [certificate____________] [Browse]    │
│ ☐ Generate as CA certificate                            │
│ ☐ Generate CSR instead of certificate                   │
│ ☐ Generate key pair only                                │
│                                                          │
│ [Generate Certificate] [Verify Certificate] [Clear]     │
└─────────────────────────────────────────────────────────┘
│ Ready                                                    │
└─────────────────────────────────────────────────────────┘
```

## Future Enhancements

Potential features for future versions:
- Certificate chain viewer
- Batch certificate generation
- Certificate renewal tracking
- Export to different formats (P12, JKS)
- Dark mode theme
- Certificate template saving/loading
- Integration with hardware security modules (HSM)

## Contributing

If you find bugs or have feature requests for the GUI:
1. Check existing issues
2. Submit detailed bug reports with screenshots
3. Include OS and Python version
4. Attach console output if available

## Related Documentation

- `README.md` - Main project documentation
- `API-README.md` - REST API documentation
- `HYBRID-GUIDE.md` - Hybrid certificate guide
- `PRODUCTION.md` - Production deployment guide
- `WARP.md` - Development guide for WARP

## License

Same license as the main project. See root LICENSE file.
