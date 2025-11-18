# Quick Start - ML-DSA Certificate Generator GUI

Generate post-quantum X.509 certificates in 3 easy steps!

## Launch the GUI

```bash
./launch-gui.sh
# or
python3 gui.py
```

## Generate Your First Certificate

### Step 1: Enter Subject Information

In the **Subject Information** section, fill in:
- **Common Name (CN)**: `example.com` (required)
- **Organization (O)**: `Example Inc` (optional)

### Step 2: Select Security Level

Choose one of:
- **ML-DSA-44** - Standard security (fastest)
- **ML-DSA-65** - Recommended default ✓
- **ML-DSA-87** - Highest security

### Step 3: Click Generate

Click the **"Generate Certificate"** button and watch the console output tab for progress.

## What You Get

Three files will be created:
- `certificate.key` - Your private key (keep secure!)
- `certificate.pub` - Your public key
- `certificate.crt` - Your certificate

## Common Use Cases

### Web Server Certificate with SANs

1. Common Name: `web.example.com`
2. Click **"Add DNS Name"**: `www.example.com`
3. Click **"Add DNS Name"**: `example.com`
4. Set Validity: `365` days
5. Output: `webserver`
6. Click **Generate Certificate**

### CA Certificate (for signing other certificates)

1. Common Name: `My Root CA`
2. Organization: `Example Inc`
3. Check ☑ **"Generate as CA certificate"**
4. Set Validity: `3650` days (10 years)
5. Output: `rootca`
6. Click **Generate Certificate**

### Certificate Signing Request (CSR)

1. Common Name: `app.example.com`
2. Check ☑ **"Generate CSR instead of certificate"**
3. Output: `app-csr`
4. Click **Generate Certificate**
5. Send `app-csr.csr` to your CA for signing

### Just Generate Keys (no certificate)

1. Common Name: `test` (required)
2. Check ☑ **"Generate key pair only"**
3. Output: `keys`
4. Click **Generate Certificate**

### Sign a CSR with Your CA (New!)

1. Click the **"Sign CSR with CA"** tab
2. **CSR file**: Browse to `app.csr` (your CSR file)
3. **CA certificate**: Browse to `rootca.crt` (your CA certificate)
4. **CA private key**: Browse to `rootca.key` (your CA key)
5. **Validity**: `365` days
6. **Output**: `signed-app`
7. Click **"Sign CSR"**
8. Result: `signed-app.crt` created

**Complete workflow example**:
1. Generate CA: CN="My CA", check CA box, output="myca"
2. Generate CSR: CN="server.example.com", check CSR box, output="server"
3. Switch to "Sign CSR with CA" tab
4. Sign CSR: Select server.csr, myca.crt, myca.key
5. You now have a CA-signed certificate!

## Verify a Certificate

1. Click **"Verify Certificate"** button
2. Browse to your `.crt` file
3. View details in the Output Console tab

## Troubleshooting

### "OpenSSL does not appear to support ML-DSA"

**Fix:** Install OQS provider first:
```bash
./install-oqs.sh
```

### "Common Name (CN) is required"

You must enter at least a Common Name before generating.

### GUI won't start

**Fix:** Install tkinter:
```bash
# macOS
brew install python-tk

# Ubuntu/Debian
sudo apt-get install python3-tk
```

## Tips

- Use the **Output Console** tab to see real-time progress
- **Browse** button lets you choose where to save files
- All options in the CLI tool are available in the GUI
- Generated files use the same format as the CLI tool

## Need More Help?

- Full GUI documentation: [GUI-README.md](GUI-README.md)
- Command-line usage: [README.md](README.md)
- API documentation: [API-README.md](docs/API-README.md)
- Project structure: [PROJECT-STRUCTURE.md](PROJECT-STRUCTURE.md)

## Comparison: When to Use What?

| Interface | Best For |
|-----------|----------|
| **GUI** (`gui.py`) | Learning, one-off certificates, visual workflow |
| **CLI** (`mldsa_cert.py`) | Automation, scripting, CI/CD |
| **API** (`api.py`) | Remote generation, web integration |

Happy certificate generation! 🔐
