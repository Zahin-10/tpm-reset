#!/usr/bin/env python3
"""
Test for PCR7 Measured Boot Digest Calculator

This test verifies the functionality of the PCR7 measured boot digest calculator.
"""

import unittest
import os
import sys
import tempfile
import uuid
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime

# Add parent directory to path for imports
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from cli.pcr7_measured_boot import (
    read_certificate, 
    extract_signature_data_from_cert,
    create_uefi_variable_data_exact,
    hash_data,
    measure_variable,
    OVMF_GUID,
    DB_VAR_NAME
)

class TestPcr7MeasuredBoot(unittest.TestCase):
    """Test cases for PCR7 measured boot digest calculator"""
    
    def setUp(self):
        """Create a test certificate"""
        # Generate a private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create a self-signed certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Test Organization"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"test.example.com"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).sign(self.private_key, hashes.SHA256())
        
        # Save the certificate to a temporary file
        self.cert_file = tempfile.NamedTemporaryFile(delete=False, suffix='.der')
        self.cert_file.write(cert.public_bytes(serialization.Encoding.DER))
        self.cert_file.close()
        
        # Save the certificate data
        self.cert_data = cert.public_bytes(serialization.Encoding.DER)
    
    def tearDown(self):
        """Clean up temporary files"""
        os.unlink(self.cert_file.name)
    
    def test_read_certificate(self):
        """Test reading a certificate"""
        cert_data = read_certificate(self.cert_file.name)
        self.assertEqual(cert_data, self.cert_data)
    
    def test_extract_signature_data(self):
        """Test extracting signature data from a certificate"""
        sig_data = extract_signature_data_from_cert(self.cert_data)
        # Signature data should be owner GUID (16 bytes of zeros) + cert data
        self.assertEqual(len(sig_data), 16 + len(self.cert_data))
        self.assertEqual(sig_data[:16], bytes([0] * 16))
        self.assertEqual(sig_data[16:], self.cert_data)
    
    def test_create_uefi_variable_data(self):
        """Test creating UEFI variable data"""
        test_guid = uuid.UUID('12345678-1234-5678-1234-567812345678')
        test_data = b'test data'
        var_data = create_uefi_variable_data_exact(DB_VAR_NAME, test_guid, test_data)
        
        # Verify the structure
        self.assertTrue(len(var_data) > 32)  # At least header size
        
        # Check that the GUID is at the beginning
        self.assertEqual(var_data[:16], test_guid.bytes_le)
    
    def test_hash_data(self):
        """Test hashing data"""
        test_data = b'test data'
        digest = hash_data(test_data)
        self.assertEqual(len(digest), 32)  # SHA-256 is 32 bytes
    
    def test_measure_variable(self):
        """Test measuring a variable"""
        sig_data = extract_signature_data_from_cert(self.cert_data)
        digest, var_log = measure_variable(OVMF_GUID, sig_data)
        
        # Verify the digest is a SHA-256 hash
        self.assertEqual(len(digest), 32)
        
        # Verify the variable log contains the OVMF GUID
        self.assertEqual(var_log[:16], OVMF_GUID.bytes_le)

if __name__ == '__main__':
    unittest.main() 