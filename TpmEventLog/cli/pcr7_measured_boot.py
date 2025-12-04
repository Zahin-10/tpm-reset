#!/usr/bin/env python3
"""
PCR7 Measured Boot Digest Calculator

This script calculates the expected PCR7 digest for UEFI Secure Boot variables.
It can be used to verify the integrity of the Secure Boot database (db) variable
measurements in PCR7.

Usage:
    python -m TpmEventLog.cli.pcr7_measured_boot --cert CERT_PATH [options]

Options:
    --cert CERT_PATH       Path to certificate in DER format
    --guid GUID            Custom GUID to use (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
    --expected DIGEST      Expected digest value to compare with
    --save FILE_PATH       Save the UEFI_VARIABLE_DATA structure to a file
    --verbose, -v          Show verbose output
"""

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import struct
import subprocess
import os
import tempfile
import binascii
import uuid
import argparse
import sys
from typing import Optional

#Example Event Structure from TCGLogs
#"Event": {
#       "VariableGUID": "d719b2cb-3d3a-4596-a3bc-dad00e67656f", ----> VendorGUID
#       "VariableName": "db",
#       "VariableData": {
#         "SignatureOwner": "77fa9abd-0359-4d32-bd60-28f4e78f784b", ----> UEFI db GUID unique to each system
#         "SignatureData": {
#           "Handle": 1899141832864,
#           "Issuer": "CN=Microsoft Root Certificate Authority 2010, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
#           "Subject": "CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"
#         }
#       }
#     }

class UefiGuid:
    """Wrapper class for UEFI GUIDs"""
    def __init__(self, guid_str=None):
        self.guid = bytes([0] * 16)
        if guid_str:
            try:
                self.guid = uuid.UUID(guid_str)
            except ValueError as e:
                raise ValueError(f"Invalid GUID format. Please use format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx") from e

    @property
    def bytes_le(self):
        return self.guid.bytes_le

    def __str__(self):
        return str(self.guid)


class Certificate:
    """Class to handle UEFI certificate operations"""
    
    def __init__(self, cert_path):
        self.cert_path = cert_path
        self.cert_data = self._read_certificate()
    
    def _read_certificate(self):
        """Read certificate in binary format"""
        try:
            with open(self.cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Verify it's a valid certificate
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            return cert_data
        except Exception as e:
            raise ValueError(f"Error loading certificate {self.cert_path}: {e}")
    
    def create_signature_data(self, owner_guid: UefiGuid):
        """Create just the EFI_SIGNATURE_DATA portion (owner GUID + cert)"""
        # EFI_SIGNATURE_DATA is just owner GUID followed by the certificate
        return owner_guid.bytes_le + self.cert_data


class UefiVariable:
    """Class to handle UEFI variables and measurements"""

    def __init__(self, name, data, vendor_guid: Optional[str]=None):
        self.name = name
        if vendor_guid :
            self.vendor_guid = uuid.UUID(vendor_guid)
        else :
            self.vendor_guid = uuid.UUID('d719b2cb-3d3a-4596-a3bc-dad00e67656f')
        self.data = data
    
    def create_variable_data(self):
        """
        Create UEFI_VARIABLE_DATA exactly as done in the UEFI code:
        
        ///
        /// UEFI_VARIABLE_DATA
        ///
        /// This structure serves as the header for measuring variables. The name of the
        /// variable (in Unicode format) should immediately follow, then the variable
        /// data.
        /// This is defined in TCG PC Client Firmware Profile Spec 00.21
        ///
        typedef struct tdUEFI_VARIABLE_DATA {
        EFI_GUID    VariableName;
        UINT64      UnicodeNameLength;
        UINT64      VariableDataLength;
        CHAR16      UnicodeName[1];
        INT8        VariableData[1];                        ///< Driver or platform-specific data
        } UEFI_VARIABLE_DATA;
        """
        # Convert variable name to UTF-16LE as in UEFI
        var_name_utf16 = self.name.encode('utf-16le')
        var_name_length = len(var_name_utf16) // 2  # Length in character count, not bytes
        
        # Calculate size of the variable data structure
        var_log_size = 16 + 8 + 8 + len(var_name_utf16) + len(self.data)
        
        # Create the buffer exactly as in the UEFI code
        var_log = bytearray(var_log_size)
        
        # Copy owner GUID (which serves as VariableName in this context) (16 bytes)
        struct.pack_into("<16s", var_log, 0, self.vendor_guid.bytes_le)
        
        # Set UnicodeNameLength (8 bytes)
        struct.pack_into("<Q", var_log, 16, var_name_length)
        
        # Set VariableDataLength (8 bytes)
        struct.pack_into("<Q", var_log, 24, len(self.data))
        
        # Copy Unicode name
        offset = 32
        var_log[offset:offset + len(var_name_utf16)] = var_name_utf16
        
        # Copy variable data immediately after the name
        offset += len(var_name_utf16)
        var_log[offset:offset + len(self.data)] = self.data
        
        return bytes(var_log)

    def measure(self):
        """Simulate the measurement of a UEFI variable into PCR7"""
        # Create the UEFI_VARIABLE_DATA structure
        var_log = self.create_variable_data()
        
        # Calculate the hash
        digest = self.hash_data(var_log)
        
        return digest, var_log
    
    @staticmethod
    def hash_data(data):
        """Calculate SHA-256 hash of data"""
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()


class MeasuredBootDigestCalculator:
    """Class to handle the calculation of PCR7 expected measurements"""
    
    DB_VAR_NAME = "db"
    
    def __init__(self, cert_path, guid_str=None, expected=None, save_path=None, verbose=False):
        self.cert_path = cert_path
        self.guid_str = guid_str
        self.expected = expected.lower() if expected else None
        self.save_path = save_path
        self.verbose = verbose
        
        # Initialize components
        self.certificate = Certificate(cert_path)
        self.owner_guid = UefiGuid(guid_str)
    
    def calculate(self):
        """Calculate the PCR7 expected measurement"""
        print(f"Certificate size: {len(self.certificate.cert_data)} bytes")
        
        # Log GUID information
        print(f"Using custom GUID for OwnerGuid/SignatureOwner: {self.owner_guid}")
        # Extract signature data, using the self.guid_str for the EFI_SIGNATURE_DATA owner
        sig_data = self.certificate.create_signature_data(self.owner_guid)
        
        # Create UEFI variable and measure it
        variable = UefiVariable(self.DB_VAR_NAME, sig_data)
        digest, var_log = variable.measure()
        digest_hex = digest.hex().lower()
        
        # Print the results
        print(f"\nVariable name: {self.DB_VAR_NAME}")
        print(f"Calculated hash: {digest_hex}")
        
        # Compare with expected digest
        match = True
        if self.expected:
            match = digest_hex == self.expected
            print(f"Expected digest: {self.expected}")
            
            if match:
                print("✅ SUCCESS: Calculated digest matches expected value!")
            else:
                print("❌ MISMATCH: Calculated digest does not match expected value")
        
        # Save the UEFI_VARIABLE_DATA structure if requested
        if self.save_path:
            with open(self.save_path, 'wb') as f:
                f.write(var_log)
            print(f"Saved UEFI_VARIABLE_DATA to {self.save_path}")
        
        # Show verbose info if requested
        if self.verbose:
            self._print_verbose_info(var_log, sig_data)
        
        return 0 if self.expected and match else 0
    
    def _print_verbose_info(self, var_log, sig_data):
        """Print verbose information"""
        print("\nVerbose information:")
        print(f"UEFI_VARIABLE_DATA size: {len(var_log)} bytes")
        print(f"SignatureData size: {len(sig_data)} bytes")
        
        # Show a hex dump of the beginning of the UEFI_VARIABLE_DATA
        print("\nFirst 64 bytes of UEFI_VARIABLE_DATA:")
        for i in range(0, min(64, len(var_log)), 16):
            hex_data = ' '.join(f"{b:02x}" for b in var_log[i:i+16])
            ascii_data = ''.join(chr(b) if 32 <= b < 127 else '.' for b in var_log[i:i+16])
            print(f"{i:04x}: {hex_data:48s}  {ascii_data}")


def parse_args():
    parser = argparse.ArgumentParser(description='Calculate UEFI Secure Boot variable digests for PCR7 measurements')
    parser.add_argument('--cert', required=True, help='Path to certificate in DER format')
    parser.add_argument('--guid', help='Custom GUID to use (in format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)')
    parser.add_argument('--expected', help='Expected digest value to compare with')
    parser.add_argument('--save', help='Save the UEFI_VARIABLE_DATA structure to a file')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    return parser.parse_args()

def main():
    args = parse_args()
    
    try:
        calculator = MeasuredBootDigestCalculator(
            cert_path=args.cert,
            guid_str=args.guid,
            expected=args.expected,
            save_path=args.save,
            verbose=args.verbose
        )
        return calculator.calculate()
    except ValueError as e:
        print(f"Error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main()) 