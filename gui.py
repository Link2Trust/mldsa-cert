#!/usr/bin/env python3
"""
ML-DSA Certificate Generator - GUI
Modern graphical interface for generating post-quantum X.509 certificates.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
import os
from pathlib import Path

# Import the certificate generator
from mldsa_cert import MLDSACertificateGenerator


class RedirectText:
    """Redirect stdout/stderr to a text widget."""
    def __init__(self, text_widget):
        self.text_widget = text_widget
    
    def write(self, string):
        self.text_widget.configure(state='normal')
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state='disabled')
    
    def flush(self):
        pass


class MLDSAGui:
    def __init__(self, root):
        self.root = root
        self.root.title("ML-DSA Certificate Generator")
        self.root.geometry("900x800")
        
        # Variables
        self.security_level = tk.StringVar(value="ml-dsa-65")
        self.subject_cn = tk.StringVar()
        self.subject_o = tk.StringVar()
        self.subject_ou = tk.StringVar()
        self.subject_c = tk.StringVar()
        self.days = tk.IntVar(value=365)
        self.output_name = tk.StringVar(value="certificate")
        self.is_ca = tk.BooleanVar(value=False)
        self.generate_csr = tk.BooleanVar(value=False)
        self.key_only = tk.BooleanVar(value=False)
        self.san_entries = []
        
        self.setup_ui()
        
    def setup_ui(self):
        """Create the GUI layout."""
        # Header
        header_frame = ttk.Frame(self.root, padding="10")
        header_frame.pack(fill=tk.X)
        
        title_label = ttk.Label(
            header_frame, 
            text="ML-DSA Certificate Generator",
            font=("Helvetica", 18, "bold")
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            header_frame,
            text="Post-Quantum X.509 Certificates (RFC 9881)",
            font=("Helvetica", 10)
        )
        subtitle_label.pack()
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Tab 1: Certificate Generation
        self.cert_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.cert_tab, text="Certificate Generation")
        self.setup_cert_tab()
        
        # Tab 2: Sign CSR with CA
        self.sign_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.sign_tab, text="Sign CSR with CA")
        self.setup_sign_tab()
        
        # Tab 3: Output Console
        self.console_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.console_tab, text="Output Console")
        self.setup_console_tab()
        
        # Status bar
        self.status_bar = ttk.Label(
            self.root, 
            text="Ready", 
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def setup_cert_tab(self):
        """Setup the certificate generation tab."""
        # Scrollable frame
        canvas = tk.Canvas(self.cert_tab)
        scrollbar = ttk.Scrollbar(self.cert_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Security Level Section
        level_frame = ttk.LabelFrame(scrollable_frame, text="Security Level", padding="10")
        level_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Radiobutton(
            level_frame, 
            text="ML-DSA-44 (NIST Level 2, ~AES-128)", 
            variable=self.security_level, 
            value="ml-dsa-44"
        ).pack(anchor=tk.W)
        
        ttk.Radiobutton(
            level_frame, 
            text="ML-DSA-65 (NIST Level 3, ~AES-192) [Recommended]", 
            variable=self.security_level, 
            value="ml-dsa-65"
        ).pack(anchor=tk.W)
        
        ttk.Radiobutton(
            level_frame, 
            text="ML-DSA-87 (NIST Level 5, ~AES-256)", 
            variable=self.security_level, 
            value="ml-dsa-87"
        ).pack(anchor=tk.W)
        
        # Subject Information Section
        subject_frame = ttk.LabelFrame(scrollable_frame, text="Subject Information", padding="10")
        subject_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(subject_frame, text="Common Name (CN):").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Entry(subject_frame, textvariable=self.subject_cn, width=40).grid(row=0, column=1, pady=2, sticky=tk.EW)
        
        ttk.Label(subject_frame, text="Organization (O):").grid(row=1, column=0, sticky=tk.W, pady=2)
        ttk.Entry(subject_frame, textvariable=self.subject_o, width=40).grid(row=1, column=1, pady=2, sticky=tk.EW)
        
        ttk.Label(subject_frame, text="Organizational Unit (OU):").grid(row=2, column=0, sticky=tk.W, pady=2)
        ttk.Entry(subject_frame, textvariable=self.subject_ou, width=40).grid(row=2, column=1, pady=2, sticky=tk.EW)
        
        ttk.Label(subject_frame, text="Country (C):").grid(row=3, column=0, sticky=tk.W, pady=2)
        ttk.Entry(subject_frame, textvariable=self.subject_c, width=40).grid(row=3, column=1, pady=2, sticky=tk.EW)
        
        subject_frame.columnconfigure(1, weight=1)
        
        # Subject Alternative Names Section
        san_frame = ttk.LabelFrame(scrollable_frame, text="Subject Alternative Names (SANs)", padding="10")
        san_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.san_listbox = tk.Listbox(san_frame, height=4)
        self.san_listbox.pack(fill=tk.X, pady=5)
        
        san_btn_frame = ttk.Frame(san_frame)
        san_btn_frame.pack(fill=tk.X)
        
        ttk.Button(san_btn_frame, text="Add DNS Name", command=self.add_dns_san).pack(side=tk.LEFT, padx=2)
        ttk.Button(san_btn_frame, text="Add IP Address", command=self.add_ip_san).pack(side=tk.LEFT, padx=2)
        ttk.Button(san_btn_frame, text="Remove Selected", command=self.remove_san).pack(side=tk.LEFT, padx=2)
        
        # Certificate Options Section
        options_frame = ttk.LabelFrame(scrollable_frame, text="Certificate Options", padding="10")
        options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(options_frame, text="Validity (days):").grid(row=0, column=0, sticky=tk.W, pady=2)
        ttk.Spinbox(options_frame, from_=1, to=7300, textvariable=self.days, width=15).grid(row=0, column=1, pady=2, sticky=tk.W)
        
        ttk.Label(options_frame, text="Output filename:").grid(row=1, column=0, sticky=tk.W, pady=2)
        output_frame = ttk.Frame(options_frame)
        output_frame.grid(row=1, column=1, pady=2, sticky=tk.EW)
        ttk.Entry(output_frame, textvariable=self.output_name, width=30).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(output_frame, text="Browse", command=self.browse_output).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(options_frame, text="Generate as CA certificate", variable=self.is_ca).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Generate CSR instead of certificate", variable=self.generate_csr).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=2)
        ttk.Checkbutton(options_frame, text="Generate key pair only", variable=self.key_only).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        options_frame.columnconfigure(1, weight=1)
        
        # Action Buttons
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.generate_btn = ttk.Button(
            button_frame, 
            text="Generate Certificate", 
            command=self.generate_certificate,
            style="Accent.TButton"
        )
        self.generate_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame, 
            text="Verify Certificate", 
            command=self.verify_certificate
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame, 
            text="Clear Console", 
            command=self.clear_console
        ).pack(side=tk.LEFT, padx=5)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def setup_sign_tab(self):
        """Setup the CSR signing tab."""
        # Scrollable frame
        canvas = tk.Canvas(self.sign_tab)
        scrollbar = ttk.Scrollbar(self.sign_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Variables for CSR signing
        self.csr_file_path = tk.StringVar()
        self.ca_cert_path = tk.StringVar()
        self.ca_key_path = tk.StringVar()
        self.signed_cert_output = tk.StringVar(value="signed-cert")
        self.sign_validity_days = tk.IntVar(value=365)
        self.sign_as_ca = tk.BooleanVar(value=False)
        
        # Instructions
        info_frame = ttk.Frame(scrollable_frame)
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        info_label = ttk.Label(
            info_frame,
            text="Sign a Certificate Signing Request (CSR) with your CA certificate",
            font=("Helvetica", 11, "bold")
        )
        info_label.pack(anchor=tk.W)
        
        desc_label = ttk.Label(
            info_frame,
            text="This will create a signed certificate from an existing CSR using your CA's private key.",
            wraplength=800
        )
        desc_label.pack(anchor=tk.W, pady=(5, 0))
        
        # CSR File Selection
        csr_frame = ttk.LabelFrame(scrollable_frame, text="Certificate Signing Request (CSR)", padding="10")
        csr_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(csr_frame, text="CSR file:").grid(row=0, column=0, sticky=tk.W, pady=5)
        csr_entry_frame = ttk.Frame(csr_frame)
        csr_entry_frame.grid(row=0, column=1, pady=5, sticky=tk.EW)
        ttk.Entry(csr_entry_frame, textvariable=self.csr_file_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(csr_entry_frame, text="Browse...", command=self.browse_csr_file).pack(side=tk.LEFT, padx=5)
        
        csr_frame.columnconfigure(1, weight=1)
        
        # CA Certificate Selection
        ca_frame = ttk.LabelFrame(scrollable_frame, text="CA Certificate & Key", padding="10")
        ca_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(ca_frame, text="CA certificate:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ca_cert_entry_frame = ttk.Frame(ca_frame)
        ca_cert_entry_frame.grid(row=0, column=1, pady=5, sticky=tk.EW)
        ttk.Entry(ca_cert_entry_frame, textvariable=self.ca_cert_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(ca_cert_entry_frame, text="Browse...", command=self.browse_ca_cert).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(ca_frame, text="CA private key:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ca_key_entry_frame = ttk.Frame(ca_frame)
        ca_key_entry_frame.grid(row=1, column=1, pady=5, sticky=tk.EW)
        ttk.Entry(ca_key_entry_frame, textvariable=self.ca_key_path, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(ca_key_entry_frame, text="Browse...", command=self.browse_ca_key).pack(side=tk.LEFT, padx=5)
        
        ca_frame.columnconfigure(1, weight=1)
        
        # Signing Options
        sign_options_frame = ttk.LabelFrame(scrollable_frame, text="Signing Options", padding="10")
        sign_options_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(sign_options_frame, text="Validity (days):").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(sign_options_frame, from_=1, to=7300, textvariable=self.sign_validity_days, width=15).grid(row=0, column=1, pady=5, sticky=tk.W)
        
        ttk.Label(sign_options_frame, text="Output filename:").grid(row=1, column=0, sticky=tk.W, pady=5)
        output_sign_frame = ttk.Frame(sign_options_frame)
        output_sign_frame.grid(row=1, column=1, pady=5, sticky=tk.EW)
        ttk.Entry(output_sign_frame, textvariable=self.signed_cert_output, width=30).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(output_sign_frame, text="Browse", command=self.browse_sign_output).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(
            sign_options_frame, 
            text="Sign as CA certificate (allows signed cert to sign other certs)", 
            variable=self.sign_as_ca
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        sign_options_frame.columnconfigure(1, weight=1)
        
        # Action Buttons
        button_frame = ttk.Frame(scrollable_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.sign_btn = ttk.Button(
            button_frame, 
            text="Sign CSR", 
            command=self.sign_csr,
            style="Accent.TButton"
        )
        self.sign_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame, 
            text="Verify Signed Certificate", 
            command=self.verify_certificate
        ).pack(side=tk.LEFT, padx=5)
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
    def setup_console_tab(self):
        """Setup the output console tab."""
        console_frame = ttk.Frame(self.console_tab)
        console_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        ttk.Label(console_frame, text="Output Log:", font=("Helvetica", 10, "bold")).pack(anchor=tk.W)
        
        self.console_text = scrolledtext.ScrolledText(
            console_frame,
            wrap=tk.WORD,
            width=80,
            height=30,
            font=("Courier", 9),
            state='disabled'
        )
        self.console_text.pack(fill=tk.BOTH, expand=True)
        
        # Redirect stdout and stderr
        sys.stdout = RedirectText(self.console_text)
        sys.stderr = RedirectText(self.console_text)
        
    def add_dns_san(self):
        """Add a DNS Subject Alternative Name."""
        dns_name = tk.simpledialog.askstring("Add DNS Name", "Enter DNS name:")
        if dns_name:
            san = f"DNS:{dns_name}"
            self.san_entries.append(san)
            self.san_listbox.insert(tk.END, san)
    
    def add_ip_san(self):
        """Add an IP Subject Alternative Name."""
        ip_address = tk.simpledialog.askstring("Add IP Address", "Enter IP address:")
        if ip_address:
            san = f"IP:{ip_address}"
            self.san_entries.append(san)
            self.san_listbox.insert(tk.END, san)
    
    def remove_san(self):
        """Remove selected SAN from the list."""
        selection = self.san_listbox.curselection()
        if selection:
            index = selection[0]
            self.san_listbox.delete(index)
            del self.san_entries[index]
    
    def browse_output(self):
        """Browse for output file location."""
        filename = filedialog.asksaveasfilename(
            defaultextension="",
            title="Select output filename (no extension)"
        )
        if filename:
            # Remove extension if added
            filename = os.path.splitext(filename)[0]
            self.output_name.set(filename)
    
    def browse_csr_file(self):
        """Browse for CSR file."""
        filename = filedialog.askopenfilename(
            title="Select CSR File",
            filetypes=[("CSR files", "*.csr"), ("PEM files", "*.pem"), ("All files", "*.*")]
        )
        if filename:
            self.csr_file_path.set(filename)
    
    def browse_ca_cert(self):
        """Browse for CA certificate file."""
        filename = filedialog.askopenfilename(
            title="Select CA Certificate",
            filetypes=[("Certificate files", "*.crt *.pem"), ("All files", "*.*")]
        )
        if filename:
            self.ca_cert_path.set(filename)
    
    def browse_ca_key(self):
        """Browse for CA private key file."""
        filename = filedialog.askopenfilename(
            title="Select CA Private Key",
            filetypes=[("Key files", "*.key *.pem"), ("All files", "*.*")]
        )
        if filename:
            self.ca_key_path.set(filename)
    
    def browse_sign_output(self):
        """Browse for signed certificate output location."""
        filename = filedialog.asksaveasfilename(
            defaultextension="",
            title="Select output filename (no extension)"
        )
        if filename:
            # Remove extension if added
            filename = os.path.splitext(filename)[0]
            self.signed_cert_output.set(filename)
    
    def build_subject(self):
        """Build the subject string from individual fields."""
        parts = []
        if self.subject_cn.get():
            parts.append(f"CN={self.subject_cn.get()}")
        if self.subject_o.get():
            parts.append(f"O={self.subject_o.get()}")
        if self.subject_ou.get():
            parts.append(f"OU={self.subject_ou.get()}")
        if self.subject_c.get():
            parts.append(f"C={self.subject_c.get()}")
        
        if not parts:
            return None
        
        return "/" + "/".join(parts)
    
    def validate_inputs(self):
        """Validate user inputs."""
        if not self.subject_cn.get():
            messagebox.showerror("Validation Error", "Common Name (CN) is required!")
            return False
        
        if not self.output_name.get():
            messagebox.showerror("Validation Error", "Output filename is required!")
            return False
        
        return True
    
    def generate_certificate(self):
        """Generate certificate in a separate thread."""
        if not self.validate_inputs():
            return
        
        self.generate_btn.configure(state='disabled')
        self.status_bar.config(text="Generating certificate...")
        self.notebook.select(self.console_tab)
        
        # Run generation in separate thread to avoid freezing UI
        thread = threading.Thread(target=self._generate_certificate_worker)
        thread.daemon = True
        thread.start()
    
    def _generate_certificate_worker(self):
        """Worker thread for certificate generation."""
        try:
            print("\n" + "="*70)
            print("Starting certificate generation...")
            print("="*70 + "\n")
            
            # Create generator
            generator = MLDSACertificateGenerator(self.security_level.get())
            
            # Check OpenSSL support
            supported, message = generator.check_openssl_support()
            print(f"OpenSSL Check: {message}")
            if not supported:
                print("\n⚠ WARNING: ML-DSA support not detected!")
                print("Install liboqs and oqs-provider first.")
                print("See README.md or run ./install-oqs.sh on macOS\n")
            
            # Build subject
            subject = self.build_subject()
            print(f"Subject: {subject}")
            print(f"Security Level: {self.security_level.get()}")
            print(f"Output: {self.output_name.get()}\n")
            
            # Generate private key
            key_file = f"{self.output_name.get()}.key"
            if not generator.generate_private_key(key_file):
                print("\n✗ Failed to generate private key!")
                self.root.after(0, lambda: self.status_bar.config(text="Failed to generate certificate"))
                self.root.after(0, lambda: self.generate_btn.configure(state='normal'))
                return
            
            # Generate public key
            pub_file = f"{self.output_name.get()}.pub"
            if not generator.generate_public_key(key_file, pub_file):
                print("\n✗ Failed to extract public key!")
                self.root.after(0, lambda: self.status_bar.config(text="Failed to generate certificate"))
                self.root.after(0, lambda: self.generate_btn.configure(state='normal'))
                return
            
            # Check if key-only mode
            if self.key_only.get():
                print("\n✓ Key pair generation complete!")
                self.root.after(0, lambda: messagebox.showinfo("Success", "Key pair generated successfully!"))
                self.root.after(0, lambda: self.status_bar.config(text="Key pair generated successfully"))
                self.root.after(0, lambda: self.generate_btn.configure(state='normal'))
                return
            
            # Generate CSR or Certificate
            if self.generate_csr.get():
                csr_file = f"{self.output_name.get()}.csr"
                san_list = self.san_entries if self.san_entries else None
                
                if generator.generate_csr(key_file, csr_file, subject, san_list):
                    print("\n✓ Certificate Signing Request generated successfully!")
                    self.root.after(0, lambda: messagebox.showinfo("Success", "CSR generated successfully!"))
                    self.root.after(0, lambda: self.status_bar.config(text="CSR generated successfully"))
                else:
                    print("\n✗ Failed to generate CSR!")
                    self.root.after(0, lambda: self.status_bar.config(text="Failed to generate CSR"))
            else:
                cert_file = f"{self.output_name.get()}.crt"
                san_list = self.san_entries if self.san_entries else None
                
                if generator.generate_self_signed_certificate(
                    key_file, 
                    cert_file, 
                    subject, 
                    self.days.get(),
                    san_list,
                    self.is_ca.get()
                ):
                    print("\n✓ Certificate generated successfully!")
                    self.root.after(0, lambda: messagebox.showinfo("Success", "Certificate generated successfully!"))
                    self.root.after(0, lambda: self.status_bar.config(text="Certificate generated successfully"))
                else:
                    print("\n✗ Failed to generate certificate!")
                    self.root.after(0, lambda: self.status_bar.config(text="Failed to generate certificate"))
            
            print("\n" + "="*70)
            
        except Exception as e:
            print(f"\n✗ Error: {str(e)}")
            self.root.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
            self.root.after(0, lambda: self.status_bar.config(text="Error occurred"))
        finally:
            self.root.after(0, lambda: self.generate_btn.configure(state='normal'))
    
    def sign_csr(self):
        """Sign a CSR with a CA certificate in a separate thread."""
        # Validate inputs
        if not self.csr_file_path.get():
            messagebox.showerror("Validation Error", "CSR file is required!")
            return
        
        if not self.ca_cert_path.get():
            messagebox.showerror("Validation Error", "CA certificate is required!")
            return
        
        if not self.ca_key_path.get():
            messagebox.showerror("Validation Error", "CA private key is required!")
            return
        
        if not self.signed_cert_output.get():
            messagebox.showerror("Validation Error", "Output filename is required!")
            return
        
        # Check if files exist
        if not os.path.exists(self.csr_file_path.get()):
            messagebox.showerror("File Error", f"CSR file not found: {self.csr_file_path.get()}")
            return
        
        if not os.path.exists(self.ca_cert_path.get()):
            messagebox.showerror("File Error", f"CA certificate not found: {self.ca_cert_path.get()}")
            return
        
        if not os.path.exists(self.ca_key_path.get()):
            messagebox.showerror("File Error", f"CA private key not found: {self.ca_key_path.get()}")
            return
        
        self.sign_btn.configure(state='disabled')
        self.status_bar.config(text="Signing CSR...")
        self.notebook.select(self.console_tab)
        
        # Run signing in separate thread to avoid freezing UI
        thread = threading.Thread(target=self._sign_csr_worker)
        thread.daemon = True
        thread.start()
    
    def _sign_csr_worker(self):
        """Worker thread for CSR signing."""
        try:
            print("\n" + "="*70)
            print("Starting CSR signing process...")
            print("="*70 + "\n")
            
            # Create generator
            generator = MLDSACertificateGenerator(self.security_level.get())
            
            print(f"CSR File: {self.csr_file_path.get()}")
            print(f"CA Certificate: {self.ca_cert_path.get()}")
            print(f"CA Private Key: {self.ca_key_path.get()}")
            print(f"Output: {self.signed_cert_output.get()}.crt")
            print(f"Validity: {self.sign_validity_days.get()} days")
            print(f"Sign as CA: {self.sign_as_ca.get()}\n")
            
            # Sign the CSR
            output_cert = f"{self.signed_cert_output.get()}.crt"
            
            if generator.sign_csr_with_ca(
                self.csr_file_path.get(),
                self.ca_cert_path.get(),
                self.ca_key_path.get(),
                output_cert,
                self.sign_validity_days.get(),
                self.sign_as_ca.get()
            ):
                print("\n✓ CSR signed successfully!")
                print(f"\nSigned certificate saved to: {output_cert}")
                self.root.after(0, lambda: messagebox.showinfo("Success", f"CSR signed successfully!\n\nCertificate saved to:\n{output_cert}"))
                self.root.after(0, lambda: self.status_bar.config(text="CSR signed successfully"))
            else:
                print("\n✗ Failed to sign CSR!")
                self.root.after(0, lambda: messagebox.showerror("Error", "Failed to sign CSR. Check the console for details."))
                self.root.after(0, lambda: self.status_bar.config(text="Failed to sign CSR"))
            
            print("\n" + "="*70)
            
        except Exception as e:
            print(f"\n✗ Error: {str(e)}")
            import traceback
            traceback.print_exc()
            self.root.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {str(e)}"))
            self.root.after(0, lambda: self.status_bar.config(text="Error occurred"))
        finally:
            self.root.after(0, lambda: self.sign_btn.configure(state='normal'))
    
    def verify_certificate(self):
        """Verify an existing certificate."""
        cert_file = filedialog.askopenfilename(
            title="Select Certificate to Verify",
            filetypes=[("Certificate files", "*.crt *.pem"), ("All files", "*.*")]
        )
        
        if cert_file:
            self.notebook.select(self.console_tab)
            self.status_bar.config(text="Verifying certificate...")
            
            try:
                generator = MLDSACertificateGenerator()
                generator.verify_certificate(cert_file)
                self.status_bar.config(text="Certificate verified")
                messagebox.showinfo("Success", "Certificate details displayed in console")
            except Exception as e:
                print(f"\n✗ Error verifying certificate: {str(e)}")
                messagebox.showerror("Error", f"Failed to verify certificate: {str(e)}")
                self.status_bar.config(text="Verification failed")
    
    def clear_console(self):
        """Clear the console output."""
        self.console_text.configure(state='normal')
        self.console_text.delete(1.0, tk.END)
        self.console_text.configure(state='disabled')
        print("Console cleared.\n")


def main():
    """Main entry point for the GUI application."""
    import tkinter.simpledialog
    
    root = tk.Tk()
    
    # Set style
    style = ttk.Style()
    style.theme_use('default')
    
    app = MLDSAGui(root)
    
    # Welcome message
    print("="*70)
    print("ML-DSA Certificate Generator - GUI")
    print("Post-Quantum X.509 Certificates (RFC 9881)")
    print("="*70)
    print("\nWelcome! Use this tool to generate post-quantum certificates.")
    print("Make sure you have OpenSSL 3.0+ with oqs-provider installed.")
    print("\nFor macOS, run: ./install-oqs.sh")
    print("="*70 + "\n")
    
    root.mainloop()


if __name__ == "__main__":
    main()
