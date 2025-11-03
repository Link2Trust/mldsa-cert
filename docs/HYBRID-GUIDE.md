# Hybrid Certificate Guide

## Overview

This guide explains how to use hybrid certificates that combine **ML-DSA** (post-quantum) and **classical** (RSA/ECDSA) cryptographic algorithms for a smooth transition to post-quantum cryptography.

## What Problem Do Hybrid Certificates Solve?

### The Quantum Threat
- Quantum computers will break RSA and ECDSA
- Timeline: possibly 10-20 years
- Need to transition now for long-term data protection

### The Compatibility Challenge
- Not all systems support ML-DSA yet
- Can't immediately switch to PQC only
- Need gradual migration path

### The Solution: Hybrid Certificates
- Provide **both** ML-DSA and classical signatures
- Allow clients to use whichever they support
- Protect against both current and future threats

## How Hybrid Certificates Work

```
┌─────────────────────────────────────────┐
│     Hybrid Certificate Generation       │
└─────────────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌──────────────┐        ┌──────────────┐
│   ML-DSA     │        │  Classical   │
│  Key Pair    │        │  Key Pair    │
│              │        │  (RSA/ECDSA) │
└──────────────┘        └──────────────┘
        │                       │
        ▼                       ▼
┌──────────────┐        ┌──────────────┐
│   ML-DSA     │        │  Classical   │
│ Certificate  │        │ Certificate  │
│ (Primary)    │        │ (Compat)     │
└──────────────┘        └──────────────┘
        │                       │
        └───────────┬───────────┘
                    ▼
            ┌──────────────┐
            │   Deploy     │
            │     Both     │
            └──────────────┘
```

## Usage Examples

### Basic Hybrid Certificate

```bash
# ML-DSA-65 + RSA-3072
python3 mldsa_cert.py \
  --subject "/CN=example.com/O=Example Corp" \
  --hybrid rsa \
  --output mycert
```

**Generated files:**
- `mycert.key` - ML-DSA private key
- `mycert_rsa.key` - RSA private key
- `mycert.crt` - Primary ML-DSA certificate
- `mycert_classical.crt` - RSA certificate for legacy clients
- `mycert_mldsa.crt` - Standalone ML-DSA cert

### Hybrid with ECDSA

```bash
# ML-DSA-65 + ECDSA P-384
python3 mldsa_cert.py \
  --subject "/CN=api.example.com" \
  --hybrid ecdsa \
  --san "DNS:www.example.com" \
  --output api
```

### High-Security Hybrid CA

```bash
# ML-DSA-87 + RSA-3072 for maximum security
python3 mldsa_cert.py \
  --level ml-dsa-87 \
  --subject "/CN=Root CA/O=Example CA" \
  --hybrid rsa \
  --ca \
  --days 7300 \
  --output root-ca
```

## Algorithm Selection Guide

### ML-DSA Levels

| Level | NIST Category | Quantum Resistance | Performance |
|-------|---------------|-------------------|-------------|
| ML-DSA-44 | 2 | AES-128 equivalent | Fast |
| ML-DSA-65 | 3 | AES-192 equivalent | Balanced ⭐ |
| ML-DSA-87 | 5 | AES-256 equivalent | Slower |

### Classical Options

| Algorithm | Key Size | Security | Performance | Compatibility |
|-----------|----------|----------|-------------|---------------|
| RSA-3072 | 3072 bits | High | Slower | Universal ⭐ |
| ECDSA P-384 | 384 bits | High | Faster | Modern |

### Recommended Combinations

**Web Servers:**
```bash
--level ml-dsa-65 --hybrid rsa
```
- Good security/performance balance
- Maximum compatibility

**APIs & Microservices:**
```bash
--level ml-dsa-65 --hybrid ecdsa
```
- Better performance
- Smaller signatures

**Critical Infrastructure:**
```bash
--level ml-dsa-87 --hybrid rsa
```
- Maximum security
- Future-proof

**IoT/Mobile:**
```bash
--level ml-dsa-44 --hybrid ecdsa
```
- Lower resource usage
- Still secure

## Deployment Strategies

### Strategy 1: Dual-Stack (Recommended)

Deploy both certificates simultaneously:

```nginx
# Nginx configuration
ssl_certificate /etc/ssl/certs/site.crt;              # ML-DSA
ssl_certificate /etc/ssl/certs/site_classical.crt;    # RSA
ssl_certificate_key /etc/ssl/private/site.key;        # ML-DSA
ssl_certificate_key /etc/ssl/private/site_rsa.key;    # RSA
```

**Pros:**
- Maximum compatibility
- Gradual transition
- Client chooses best option

**Cons:**
- Slightly larger handshakes
- More certificates to manage

### Strategy 2: Progressive Rollout

**Phase 1 (Weeks 1-4):**
- Deploy hybrid certificates to test environments
- Monitor for compatibility issues

**Phase 2 (Weeks 5-8):**
- Roll out to production
- Track which clients use ML-DSA vs classical

**Phase 3 (Month 3+):**
- Analyze usage data
- Plan transition to ML-DSA only

### Strategy 3: Client Detection

Use SNI or User-Agent to serve appropriate certificate:

```python
def select_certificate(client_info):
    if client_supports_mldsa(client_info):
        return "site.crt"  # ML-DSA
    else:
        return "site_classical.crt"  # RSA
```

## Certificate Size Comparison

Hybrid certificates are larger due to post-quantum signatures:

| Certificate Type | Approximate Size |
|------------------|------------------|
| RSA-3072 | ~1.5 KB |
| ECDSA P-384 | ~1.0 KB |
| ML-DSA-44 | ~4.0 KB |
| ML-DSA-65 | ~5.5 KB |
| ML-DSA-87 | ~7.0 KB |
| Hybrid (ML-DSA-65 + RSA) | ~7.0 KB total |

## Security Considerations

### Strengths

✅ **Quantum-resistant**: ML-DSA protects against quantum attacks  
✅ **Backward compatible**: Classical signature for legacy systems  
✅ **Defense in depth**: Two independent signature algorithms  
✅ **Standards compliant**: RFC 9881 + classical standards

### Important Notes

⚠️ **Key Management**: Protect both private keys equally  
⚠️ **Certificate Rotation**: Update both certificates together  
⚠️ **Storage**: ML-DSA keys are larger (~4KB vs ~1KB)  
⚠️ **Performance**: ML-DSA operations are slower than RSA

## Verification

### Check ML-DSA Certificate

```bash
openssl x509 -in mycert.crt -noout -text | grep "Signature Algorithm"
# Output: Signature Algorithm: ML-DSA-65
```

### Check Classical Certificate

```bash
openssl x509 -in mycert_classical.crt -noout -text | grep "Signature Algorithm"
# Output: Signature Algorithm: sha256WithRSAEncryption
```

### Verify Both Work

```bash
# Verify ML-DSA cert
openssl verify -CAfile ca.crt mycert.crt

# Verify classical cert
openssl verify -CAfile ca_classical.crt mycert_classical.crt
```

## Troubleshooting

### Issue: Certificate too large for protocol

**Solution:** Use ECDSA instead of RSA
```bash
--hybrid ecdsa  # Smaller than RSA
```

### Issue: Client doesn't support ML-DSA

**Solution:** Use classical certificate
```bash
# Server should present both, client chooses
```

### Issue: Performance concerns

**Solution:** Use lower ML-DSA level
```bash
--level ml-dsa-44  # Faster than -65 or -87
```

## Migration Timeline Example

### Months 1-3: Preparation
- Generate hybrid certificates
- Test in staging environment
- Update monitoring

### Months 4-6: Initial Deployment
- Deploy to 10% of infrastructure
- Monitor client behavior
- Gather performance data

### Months 7-12: Full Deployment
- Roll out to all systems
- Track ML-DSA adoption rate
- Maintain classical fallback

### Year 2+: Pure PQC
- When 95%+ clients support ML-DSA
- Transition to ML-DSA-only certificates
- Deprecate classical certificates

## Best Practices

1. **Always test first**: Deploy to staging before production
2. **Monitor actively**: Track which certificate type clients use
3. **Document everything**: Keep records of certificate types and locations
4. **Plan rotation**: Establish certificate renewal procedures
5. **Stay informed**: Follow NIST and IETF updates on PQC standards
6. **Use automation**: Script certificate generation and renewal
7. **Backup keys**: Store both ML-DSA and classical keys securely
8. **Measure impact**: Monitor performance and compatibility

## Additional Resources

- [RFC 9881 - ML-DSA in X.509](https://www.rfc-editor.org/rfc/rfc9881.html)
- [NIST FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Open Quantum Safe Project](https://openquantumsafe.org/)
- [PQC Migration Guide (NIST)](https://csrc.nist.gov/Projects/post-quantum-cryptography)

## Support

For issues or questions about hybrid certificates:
1. Check the main [README.md](README.md)
2. Review example scripts: `example-hybrid.sh`
3. Consult RFC 9881 for technical specifications
4. Test with the verification tools included

---

**Remember**: Hybrid certificates are a transition mechanism. The end goal is full post-quantum cryptography, but hybrid certificates provide a safe bridge to get there.
