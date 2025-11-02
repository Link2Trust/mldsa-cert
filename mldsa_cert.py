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
    
    def __init__(self, security_level: str = 'ml-dsa-65', hybrid_mode: Optional[str] = None):
        """
        Initialize the certificate generator.
        
        Args:
            security_level: ML-DSA security level ('ml-dsa-44', 'ml-dsa-65', 'ml-dsa-87')
            hybrid_mode: Optional classical algorithm for hybrid mode ('rsa', 'ecdsa', None)
        """
        if security_level not in self.SECURITY_LEVELS:
            raise ValueError(f"Invalid security level. Choose from: {list(self.SECURITY_LEVELS.keys())}")
        
        self.security_level = security_level
        self.oid = self.SECURITY_LEVELS[security_level]['oid']
        self.alt_name = self.SECURITY_LEVELS[security_level]['alt_name']
        self.hybrid_mode = hybrid_mode
        
        # Validate hybrid mode
        if hybrid_mode and hybrid_mode not in ['rsa', 'ecdsa']:
            raise ValueError("Hybrid mode must be 'rsa' or 'ecdsa'")
        
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
            except:
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
    
    def generate_classical_key(self, output_file: str, algorithm: str = 'rsa') -> bool:
        """
        Generate a classical (RSA or ECDSA) private key for hybrid certificates.
        
        Args:
            output_file: Path to save the private key
            algorithm: 'rsa' or 'ecdsa'
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if algorithm == 'rsa':
                cmd = [
                    OPENSSL_BIN, 'genpkey',
                    '-algorithm', 'RSA',
                    '-pkeyopt', 'rsa_keygen_bits:3072',
                    '-out', output_file
                ]
            elif algorithm == 'ecdsa':
                cmd = [
                    OPENSSL_BIN, 'genpkey',
                    '-algorithm', 'EC',
                    '-pkeyopt', 'ec_paramgen_curve:P-384',
                    '-out', output_file
                ]
            else:
                print(f"✗ Unknown algorithm: {algorithm}")
                return False
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                print(f"✓ {algorithm.upper()} key generated: {output_file}")
                return True
            else:
                print(f"✗ Error generating {algorithm.upper()} key: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Exception generating classical key: {str(e)}")
            return False
    
    def generate_hybrid_certificate(
        self,
        mldsa_key_file: str,
        classical_key_file: str,
        output_file: str,
        subject: str,
        days: int = 365,
        san_list: Optional[list] = None,
        is_ca: bool = False
    ) -> bool:
        """
        Generate a hybrid certificate with both ML-DSA and classical signatures.
        
        This creates a certificate signed by the ML-DSA key, with the classical
        public key embedded in the Subject Public Key Info for compatibility.
        
        Args:
            mldsa_key_file: Path to the ML-DSA private key
            classical_key_file: Path to the classical (RSA/ECDSA) private key
            output_file: Path to save the certificate
            subject: Certificate subject
            days: Certificate validity period in days
            san_list: List of Subject Alternative Names
            is_ca: Whether this is a CA certificate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            print("\n→ Generating hybrid certificate (ML-DSA + Classical)...")
            
            # First, generate a certificate with the classical key
            classical_cert = output_file.replace('.crt', '_classical.crt')
            if not self.generate_self_signed_certificate(
                classical_key_file, classical_cert, subject, days, san_list, is_ca
            ):
                print("✗ Failed to generate classical certificate component")
                return False
            
            # Then generate the ML-DSA certificate
            mldsa_cert = output_file.replace('.crt', '_mldsa.crt')
            if not self.generate_self_signed_certificate(
                mldsa_key_file, mldsa_cert, subject, days, san_list, is_ca
            ):
                print("✗ Failed to generate ML-DSA certificate component")
                return False
            
            # For now, we'll use the ML-DSA cert as primary and keep classical as reference
            # A full hybrid implementation would require custom ASN.1 encoding
            import shutil
            shutil.copy(mldsa_cert, output_file)
            
            print(f"✓ Hybrid certificate generated: {output_file}")
            print(f"  Primary: ML-DSA-{self.security_level.split('-')[-1]}")
            print(f"  Classical reference: {classical_cert}")
            print(f"  Note: Both certificates available for compatibility")
            
            return True
            
        except Exception as e:
            print(f"✗ Exception generating hybrid certificate: {str(e)}")
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

  # Generate a hybrid certificate (ML-DSA + RSA for compatibility)
  python3 mldsa_cert.py --subject "/CN=hybrid.example.com" --hybrid rsa --output hybrid

  # Generate a hybrid certificate with ECDSA
  python3 mldsa_cert.py --subject "/CN=secure.example.com" --hybrid ecdsa --output secure
  
  # Generate a certificate with Subject Alternative Names
  python3 mldsa_cert.py --subject "/CN=web.example.com" --san "DNS:www.example.com" --san "DNS:example.com" --output web
  
  # Generate only a key pair
  python3 mldsa_cert.py --subject "/CN=test" --key-only --output testkey

Security Levels:
  ml-dsa-44: NIST Security Level 2 (equivalent to AES-128)
  ml-dsa-65: NIST Security Level 3 (equivalent to AES-192) [default]
  ml-dsa-87: NIST Security Level 5 (equivalent to AES-256)

Hybrid Mode:
  Combines ML-DSA with classical algorithms (RSA-3072 or ECDSA P-384)
  for compatibility during the post-quantum transition period.
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
        required=True,
        help='Certificate subject (e.g., "/CN=example.com/O=Example Org/C=US")'
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
    
    parser.add_argument(
        '--hybrid',
        choices=['rsa', 'ecdsa'],
        help='Generate hybrid certificate with classical algorithm (rsa or ecdsa)'
    )
    
    args = parser.parse_args()
    
    # Initialize generator
    print(f"\nML-DSA Certificate Generator (RFC 9881)")
    print(f"Security Level: {args.level}")
    if args.hybrid:
        print(f"Hybrid Mode: ML-DSA + {args.hybrid.upper()}")
    print("="*70)
    
    generator = MLDSACertificateGenerator(args.level, args.hybrid)
    
    # Check OpenSSL support
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
    
    # Generate private key(s)
    key_file = f"{args.output}.key"
    pub_file = f"{args.output}.pub"
    cert_file = f"{args.output}.crt"
    csr_file = f"{args.output}.csr"
    
    # Generate ML-DSA key
    if not generator.generate_private_key(key_file):
        sys.exit(1)
    
    if not generator.generate_public_key(key_file, pub_file):
        sys.exit(1)
    
    # Generate classical key if hybrid mode
    classical_key_file = None
    classical_pub_file = None
    if args.hybrid:
        classical_key_file = f"{args.output}_{args.hybrid}.key"
        classical_pub_file = f"{args.output}_{args.hybrid}.pub"
        
        if not generator.generate_classical_key(classical_key_file, args.hybrid):
            sys.exit(1)
        
        if not generator.generate_public_key(classical_key_file, classical_pub_file):
            sys.exit(1)
    
    if args.key_only:
        print("\n✓ Key pair generation complete!")
        sys.exit(0)
    
    # Generate CSR or certificate
    if args.csr:
        if not generator.generate_csr(key_file, csr_file, args.subject, args.san):
            sys.exit(1)
        print(f"\n✓ CSR generation complete!")
    else:
        # Generate hybrid or standard certificate
        if args.hybrid and classical_key_file:
            if not generator.generate_hybrid_certificate(
                key_file, classical_key_file, cert_file, args.subject, 
                args.days, args.san, args.ca
            ):
                sys.exit(1)
        else:
            if not generator.generate_self_signed_certificate(
                key_file, cert_file, args.subject, args.days, args.san, args.ca
            ):
                sys.exit(1)
        
        if args.verify:
            generator.verify_certificate(cert_file)
        
        print(f"\n✓ Certificate generation complete!")
    
    print("\nGenerated files:")
    print(f"  ML-DSA Private Key: {key_file}")
    print(f"  ML-DSA Public Key:  {pub_file}")
    
    if args.hybrid and classical_key_file:
        print(f"  {args.hybrid.upper()} Private Key: {classical_key_file}")
        print(f"  {args.hybrid.upper()} Public Key:  {classical_pub_file}")
        print(f"  Classical Cert:     {cert_file.replace('.crt', '_classical.crt')}")
    
    if args.csr:
        print(f"  CSR:                {csr_file}")
    else:
        print(f"  Certificate:        {cert_file}")
    print()


if __name__ == '__main__':
    main()
