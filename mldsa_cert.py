#!/usr/bin/env python3
"""
ML-DSA Certificate Generator
Generates X.509 certificates using ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
according to RFC 9881 specifications.

ML-DSA was formerly known as CRYSTALS-Dilithium and is a NIST-selected
post-quantum cryptographic signature algorithm.
"""

import subprocess
import os
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Tuple
import argparse

# Set OpenSSL binary and config for oqs-provider support
OPENSSL_BIN = '/usr/local/opt/openssl@3/bin/openssl'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OPENSSL_CONF = os.path.join(SCRIPT_DIR, 'openssl-oqs.cnf')

# Use Homebrew OpenSSL 3 if system openssl is LibreSSL
if not os.path.exists(OPENSSL_BIN):
    # Fallback to system openssl
    OPENSSL_BIN = 'openssl'

# Set environment for all subprocess calls
if os.path.exists(OPENSSL_CONF):
    os.environ['OPENSSL_CONF'] = OPENSSL_CONF


class MLDSACertificateGenerator:
    """
    Generates ML-DSA certificates compliant with RFC 9881.
    
    RFC 9881 defines the use of ML-DSA in Internet X.509 certificates.
    ML-DSA security levels:
    - ML-DSA-44: NIST Security Level 2
    - ML-DSA-65: NIST Security Level 3
    - ML-DSA-87: NIST Security Level 5
    """
    
    # OIDs from RFC 9881 for ML-DSA
    ML_DSA_44_OID = "2.16.840.1.101.3.4.3.17"  # id-ml-dsa-44
    ML_DSA_65_OID = "2.16.840.1.101.3.4.3.18"  # id-ml-dsa-65
    ML_DSA_87_OID = "2.16.840.1.101.3.4.3.19"  # id-ml-dsa-87
    
    SECURITY_LEVELS = {
        'ml-dsa-44': {'oid': ML_DSA_44_OID, 'level': 2, 'alt_name': 'dilithium2'},
        'ml-dsa-65': {'oid': ML_DSA_65_OID, 'level': 3, 'alt_name': 'dilithium3'},
        'ml-dsa-87': {'oid': ML_DSA_87_OID, 'level': 5, 'alt_name': 'dilithium5'},
    }
    
    def __init__(self, security_level: str = 'ml-dsa-65'):
        """
        Initialize the certificate generator.
        
        Args:
            security_level: ML-DSA security level ('ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87')
        """
        if security_level not in self.SECURITY_LEVELS:
            raise ValueError(f"Invalid security level. Choose from: {list(self.SECURITY_LEVELS.keys())}")
        
        self.security_level = security_level
        self.oid = self.SECURITY_LEVELS[security_level]['oid']
        self.alt_name = self.SECURITY_LEVELS[security_level]['alt_name']
        
    def check_openssl_support(self) -> Tuple[bool, str]:
        """
        Check if OpenSSL supports ML-DSA/Dilithium algorithms.
        
        Returns:
            Tuple of (supported: bool, message: str)
        """
        try:
            result = subprocess.run(
                [OPENSSL_BIN, 'list', '-providers'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            # Check for oqsprovider or similar post-quantum provider
            if 'oqsprovider' in result.stdout.lower() or 'dilithium' in result.stdout.lower():
                return True, "OpenSSL has post-quantum cryptography support"
            
            # Try to check if we can generate a key
            try:
                test_result = subprocess.run(
                    [OPENSSL_BIN, 'genpkey', '-algorithm', self.alt_name, '-help'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if test_result.returncode == 0 or 'dilithium' in test_result.stderr.lower():
                    return True, "OpenSSL supports Dilithium/ML-DSA"
            except (subprocess.TimeoutExpired, OSError):
                pass
            
            return False, "OpenSSL does not appear to support ML-DSA. Install liboqs and oqs-provider."
            
        except Exception as e:
            return False, f"Error checking OpenSSL: {str(e)}"
    
    def generate_private_key(self, output_file: str) -> bool:
        """
        Generate an ML-DSA private key.
        
        Args:
            output_file: Path to save the private key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Try with ML-DSA algorithm name first
            cmd = [
                OPENSSL_BIN, 'genpkey',
                '-algorithm', self.security_level,
                '-out', output_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                # Try with Dilithium name as fallback
                cmd = [
                    OPENSSL_BIN, 'genpkey',
                    '-algorithm', self.alt_name,
                    '-out', output_file
                ]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"✓ Private key generated: {output_file}")
                return True
            else:
                print(f"✗ Error generating private key: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Exception generating private key: {str(e)}")
            return False
    
    def generate_public_key(self, private_key_file: str, output_file: str) -> bool:
        """
        Extract public key from private key.
        
        Args:
            private_key_file: Path to the private key
            output_file: Path to save the public key
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = [
                OPENSSL_BIN, 'pkey',
                '-in', private_key_file,
                '-pubout',
                '-out', output_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"✓ Public key extracted: {output_file}")
                return True
            else:
                print(f"✗ Error extracting public key: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Exception extracting public key: {str(e)}")
            return False
    
    def create_certificate_config(self, subject: str, days: int = 365, 
                                  san_list: Optional[list] = None) -> str:
        """
        Create OpenSSL configuration for certificate generation.
        
        Args:
            subject: Certificate subject (e.g., "/CN=example.com/O=Example Org")
            days: Certificate validity period in days
            san_list: List of Subject Alternative Names
            
        Returns:
            Configuration file content as string
        """
        san_entries = ""
        if san_list:
            san_entries = "subjectAltName = @alt_names\n\n[alt_names]\n"
            for idx, san in enumerate(san_list, 1):
                if san.startswith('DNS:') or san.startswith('IP:'):
                    san_entries += f"{san}\n"
                else:
                    san_entries += f"DNS.{idx} = {san}\n"
        
        config = f"""[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
x509_extensions = v3_ca
prompt = no

[ req_distinguished_name ]
# Subject is set via command line

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,digitalSignature,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
{san_entries}

[ v3_end ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
{san_entries}
"""
        return config
    
    def generate_self_signed_certificate(
        self,
        private_key_file: str,
        output_file: str,
        subject: str,
        days: int = 365,
        san_list: Optional[list] = None,
        is_ca: bool = False
    ) -> bool:
        """
        Generate a self-signed X.509 certificate using ML-DSA.
        
        Args:
            private_key_file: Path to the ML-DSA private key
            output_file: Path to save the certificate
            subject: Certificate subject (e.g., "/CN=example.com/O=Example Org")
            days: Certificate validity period in days
            san_list: List of Subject Alternative Names
            is_ca: Whether this is a CA certificate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create temporary config file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cnf', delete=False) as f:
                config_content = self.create_certificate_config(subject, days, san_list)
                f.write(config_content)
                config_file = f.name
            
            try:
                extension = 'v3_ca' if is_ca else 'v3_end'
                
                cmd = [
                    OPENSSL_BIN, 'req',
                    '-new',
                    '-x509',
                    '-key', private_key_file,
                    '-out', output_file,
                    '-days', str(days),
                    '-config', config_file,
                    '-extensions', extension,
                    '-subj', subject
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"✓ Certificate generated: {output_file}")
                    print(f"  Subject: {subject}")
                    print(f"  Validity: {days} days")
                    print(f"  Algorithm: {self.security_level} (OID: {self.oid})")
                    return True
                else:
                    print(f"✗ Error generating certificate: {result.stderr}")
                    return False
                    
            finally:
                os.unlink(config_file)
                
        except Exception as e:
            print(f"✗ Exception generating certificate: {str(e)}")
            return False
    
    def generate_csr(
        self,
        private_key_file: str,
        output_file: str,
        subject: str,
        san_list: Optional[list] = None
    ) -> bool:
        """
        Generate a Certificate Signing Request (CSR).
        
        Args:
            private_key_file: Path to the ML-DSA private key
            output_file: Path to save the CSR
            subject: Certificate subject
            san_list: List of Subject Alternative Names
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cnf', delete=False) as f:
                config_content = self.create_certificate_config(subject, san_list=san_list)
                f.write(config_content)
                config_file = f.name
            
            try:
                cmd = [
                    OPENSSL_BIN, 'req',
                    '-new',
                    '-key', private_key_file,
                    '-out', output_file,
                    '-config', config_file,
                    '-subj', subject
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"✓ CSR generated: {output_file}")
                    return True
                else:
                    print(f"✗ Error generating CSR: {result.stderr}")
                    return False
                    
            finally:
                os.unlink(config_file)
                
        except Exception as e:
            print(f"✗ Exception generating CSR: {str(e)}")
            return False
    
    def sign_csr_with_ca(
        self,
        csr_file: str,
        ca_cert_file: str,
        ca_key_file: str,
        output_file: str,
        days: int = 365,
        is_ca: bool = False
    ) -> bool:
        """
        Sign a Certificate Signing Request (CSR) with a CA certificate.
        
        Args:
            csr_file: Path to the CSR file
            ca_cert_file: Path to the CA certificate
            ca_key_file: Path to the CA private key
            output_file: Path to save the signed certificate
            days: Certificate validity period in days
            is_ca: Whether the signed certificate should be a CA certificate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create temporary config file for extensions
            with tempfile.NamedTemporaryFile(mode='w', suffix='.cnf', delete=False) as f:
                extension = 'v3_ca' if is_ca else 'v3_end'
                config_content = self.create_certificate_config(
                    subject="",  # Subject comes from CSR
                    days=days,
                    san_list=None  # SANs come from CSR
                )
                f.write(config_content)
                config_file = f.name
            
            try:
                extension = 'v3_ca' if is_ca else 'v3_end'
                
                cmd = [
                    OPENSSL_BIN, 'x509',
                    '-req',
                    '-in', csr_file,
                    '-CA', ca_cert_file,
                    '-CAkey', ca_key_file,
                    '-CAcreateserial',
                    '-out', output_file,
                    '-days', str(days),
                    '-extfile', config_file,
                    '-extensions', extension
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print(f"✓ Certificate signed: {output_file}")
                    print(f"  CA: {ca_cert_file}")
                    print(f"  Validity: {days} days")
                    print(f"  Algorithm: {self.security_level} (OID: {self.oid})")
                    return True
                else:
                    print(f"✗ Error signing certificate: {result.stderr}")
                    return False
                    
            finally:
                os.unlink(config_file)
                
        except Exception as e:
            print(f"✗ Exception signing certificate: {str(e)}")
            return False
    
    def verify_certificate(self, cert_file: str) -> bool:
        """
        Verify and display certificate information.
        
        Args:
            cert_file: Path to the certificate file
            
        Returns:
            True if verification successful, False otherwise
        """
        try:
            cmd = [OPENSSL_BIN, 'x509', '-in', cert_file, '-text', '-noout']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                print("\n" + "="*70)
                print("CERTIFICATE DETAILS")
                print("="*70)
                print(result.stdout)
                return True
            else:
                print(f"✗ Error verifying certificate: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Exception verifying certificate: {str(e)}")
            return False


def print_header(args):
    """Print application header and configuration."""
    print("\nML-DSA Certificate Generator (RFC 9881)")
    print(f"Security Level: {args.level}")
    print("="*70)


def check_and_warn_openssl_support(generator):
    """Check OpenSSL support and print warnings if needed."""
    supported, message = generator.check_openssl_support()
    print(f"\nOpenSSL Check: {message}")
    if not supported:
        print("\n⚠ WARNING: ML-DSA support not detected in OpenSSL.")
        print("To use this tool, you need:")
        print("  1. OpenSSL 3.0+ with liboqs integration")
        print("  2. oqs-provider installed")
        print("\nInstallation guide: https://github.com/open-quantum-safe/oqs-provider")
        print("\nProceeding anyway (may fail)...")
    print("\n" + "="*70)


def generate_keys(generator, args):
    """Generate ML-DSA keys.
    
    Returns:
        Tuple of (key_file, pub_file)
    """
    key_file = f"{args.output}.key"
    pub_file = f"{args.output}.pub"
    
    # Generate ML-DSA key
    if not generator.generate_private_key(key_file):
        sys.exit(1)
    
    if not generator.generate_public_key(key_file, pub_file):
        sys.exit(1)
    
    return key_file, pub_file


def _generate_csr_workflow(generator, key_file, csr_file, args):
    """Generate CSR workflow."""
    if not generator.generate_csr(key_file, csr_file, args.subject, args.san):
        sys.exit(1)
    print("\n✓ CSR generation complete!")


def _generate_certificate_workflow(generator, args, key_file, cert_file):
    """Generate certificate workflow."""
    success = generator.generate_self_signed_certificate(
        key_file, cert_file, args.subject, args.days, args.san, args.ca
    )
    
    if not success:
        sys.exit(1)
    
    if args.verify:
        generator.verify_certificate(cert_file)
    
    print("\n✓ Certificate generation complete!")


def generate_certificate_or_csr(generator, args, key_file):
    """Generate certificate or CSR based on arguments.
    
    Returns:
        Tuple of (cert_file, csr_file)
    """
    cert_file = f"{args.output}.crt"
    csr_file = f"{args.output}.csr"
    
    if args.csr:
        _generate_csr_workflow(generator, key_file, csr_file, args)
    else:
        _generate_certificate_workflow(generator, args, key_file, cert_file)
    
    return cert_file, csr_file


def print_generated_files(args, key_file, pub_file, cert_file, csr_file):
    """Print summary of generated files."""
    print("\nGenerated files:")
    print(f"  ML-DSA Private Key: {key_file}")
    print(f"  ML-DSA Public Key:  {pub_file}")
    
    if args.csr:
        print(f"  CSR:                {csr_file}")
    else:
        print(f"  Certificate:        {cert_file}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Generate ML-DSA (Post-Quantum) X.509 Certificates (RFC 9881)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate a self-signed certificate with ML-DSA-65 (default)
  python3 mldsa_cert.py --subject "/CN=example.com/O=Example Org" --output mycert

  # Generate a CA certificate with ML-DSA-87 (highest security)
  python3 mldsa_cert.py --level ml-dsa-87 --subject "/CN=My CA/O=Example" --ca --output ca

  # Generate a certificate with Subject Alternative Names
  python3 mldsa_cert.py --subject "/CN=web.example.com" --san "DNS:www.example.com" --san "DNS:example.com" --output web
  
  # Generate a CSR
  python3 mldsa_cert.py --subject "/CN=server.example.com" --csr --output server
  
  # Sign a CSR with a CA certificate
  python3 mldsa_cert.py --sign-csr server.csr --ca-cert ca.crt --ca-key ca.key --output server-signed --days 365
  
  # Generate only a key pair
  python3 mldsa_cert.py --subject "/CN=test" --key-only --output testkey

Security Levels:
  ml-dsa-44: NIST Security Level 2 (equivalent to AES-128)
  ml-dsa-65: NIST Security Level 3 (equivalent to AES-192) [default]
  ml-dsa-87: NIST Security Level 5 (equivalent to AES-256)
        """
    )
    
    parser.add_argument(
        '--level',
        choices=['ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87'],
        default='ml-dsa-65',
        help='ML-DSA security level (default: ml-dsa-65)'
    )
    
    parser.add_argument(
        '--subject',
        help='Certificate subject (e.g., "/CN=example.com/O=Example Org/C=US") [required unless using --sign-csr]'
    )
    
    parser.add_argument(
        '--output',
        required=True,
        help='Output file prefix (will create .key, .pub, .crt files)'
    )
    
    parser.add_argument(
        '--days',
        type=int,
        default=365,
        help='Certificate validity period in days (default: 365)'
    )
    
    parser.add_argument(
        '--san',
        action='append',
        help='Subject Alternative Name (can be specified multiple times)'
    )
    
    parser.add_argument(
        '--ca',
        action='store_true',
        help='Generate a CA certificate'
    )
    
    parser.add_argument(
        '--csr',
        action='store_true',
        help='Generate a CSR instead of self-signed certificate'
    )
    
    parser.add_argument(
        '--key-only',
        action='store_true',
        help='Generate only the key pair (no certificate)'
    )
    
    parser.add_argument(
        '--verify',
        action='store_true',
        help='Verify and display certificate details after generation'
    )
    
    # CSR signing arguments
    parser.add_argument(
        '--sign-csr',
        metavar='CSR_FILE',
        help='Sign a CSR with a CA certificate (requires --ca-cert and --ca-key)'
    )
    
    parser.add_argument(
        '--ca-cert',
        metavar='CA_CERT',
        help='CA certificate file for signing CSRs'
    )
    
    parser.add_argument(
        '--ca-key',
        metavar='CA_KEY',
        help='CA private key file for signing CSRs'
    )
    
    args = parser.parse_args()
    
    # Validate arguments based on mode
    if args.sign_csr:
        # CSR signing mode - subject not required
        if not args.output:
            print("Error: --output is required")
            sys.exit(1)
    else:
        # Certificate/CSR generation mode - subject is required
        if not args.subject:
            print("Error: --subject is required (unless using --sign-csr)")
            sys.exit(1)
        if not args.output:
            print("Error: --output is required")
            sys.exit(1)
    
    # Check if this is a CSR signing operation
    if args.sign_csr:
        # Validate CSR signing arguments
        if not args.ca_cert:
            print("Error: --ca-cert is required when using --sign-csr")
            sys.exit(1)
        if not args.ca_key:
            print("Error: --ca-key is required when using --sign-csr")
            sys.exit(1)
        
        # Check if files exist
        if not os.path.exists(args.sign_csr):
            print(f"Error: CSR file not found: {args.sign_csr}")
            sys.exit(1)
        if not os.path.exists(args.ca_cert):
            print(f"Error: CA certificate not found: {args.ca_cert}")
            sys.exit(1)
        if not os.path.exists(args.ca_key):
            print(f"Error: CA private key not found: {args.ca_key}")
            sys.exit(1)
        
        # Initialize generator for CSR signing
        print("\nML-DSA CSR Signing (RFC 9881)")
        print(f"Security Level: {args.level}")
        print("="*70)
        generator = MLDSACertificateGenerator(args.level)
        
        print(f"\nCSR File:        {args.sign_csr}")
        print(f"CA Certificate:  {args.ca_cert}")
        print(f"CA Private Key:  {args.ca_key}")
        print(f"Output:          {args.output}.crt")
        print(f"Validity:        {args.days} days")
        print(f"CA Certificate:  {args.ca}")
        print()
        
        # Sign the CSR
        output_cert = f"{args.output}.crt"
        success = generator.sign_csr_with_ca(
            args.sign_csr,
            args.ca_cert,
            args.ca_key,
            output_cert,
            args.days,
            args.ca
        )
        
        if not success:
            sys.exit(1)
        
        if args.verify:
            generator.verify_certificate(output_cert)
        
        print("\n✓ CSR signing complete!")
        print(f"\nSigned certificate: {output_cert}")
        print()
        sys.exit(0)
    
    # Standard certificate/CSR generation workflow
    # Initialize generator
    print_header(args)
    generator = MLDSACertificateGenerator(args.level)
    
    # Check OpenSSL support
    check_and_warn_openssl_support(generator)
    
    # Generate keys
    key_file, pub_file = generate_keys(generator, args)
    
    if args.key_only:
        print("\n✓ Key pair generation complete!")
        print_generated_files(args, key_file, pub_file, 
                            f"{args.output}.crt", f"{args.output}.csr")
        sys.exit(0)
    
    # Generate certificate or CSR
    cert_file, csr_file = generate_certificate_or_csr(generator, args, key_file)
    
    # Print summary
    print_generated_files(args, key_file, pub_file, cert_file, csr_file)


if __name__ == '__main__':
    main()
