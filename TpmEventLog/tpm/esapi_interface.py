#!/usr/bin/env python3

"""
TPM ESAPI Interface Module

This module provides a wrapper for interacting with the TPM through the TPM2 ESAPI
interface for operations like PCR extensions.
"""

import os
import sys
import hashlib
from typing import Dict, List, Any, Optional

# Set a flag to check if tpm2_pytss is available
TPM2_PYTSS_AVAILABLE = False

try:
    # Import the required classes from tpm2_pytss
    from tpm2_pytss import ESAPI, ESYS_TR, TPM2B_NONCE, TPMT_SYM_DEF, TPML_PCR_SELECTION, TPM2B_DIGEST
    from tpm2_pytss.constants import TPM2_ALG, TPM2_RH
    from tpm2_pytss.types import TPML_DIGEST_VALUES, TPMT_HA
    # Import successful
    TPM2_PYTSS_AVAILABLE = True
except ImportError as e:
    # Import failed, but we'll continue without crashing
    print(f"Warning: tpm2_pytss import failed: {e}")
    print("TPM functionality will be limited")


class ESAPIInterface:
    """
    Interface to the TPM ESAPI for PCR operations.
    """

    def __init__(self, tcti_connection: str = None):
        """
        Initialize the ESAPI interface.
        
        Args:
            tcti_connection: TPM connection string (e.g., "swtpm:host=localhost,port=2321")
                            If None, will try to use the default TCTI.
        """
        self.tcti_connection = tcti_connection
        self.ctx = None
        self.connected = False

    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

    def connect(self):
        """
        Connect to the TPM using ESAPI.
        
        Returns:
            bool: True if connection successful, False otherwise.
        """
        if not TPM2_PYTSS_AVAILABLE:
            print("TPM2_PYTSS not available, can't connect to TPM")
            return False
            
        try:
            # Create the ESAPI context with the tcti parameter
            if self.tcti_connection:
                self.ctx = ESAPI(tcti=self.tcti_connection)
                print(f"Connected to TPM via ESAPI with TCTI {self.tcti_connection}")
            else:
                # Use default TCTI
                self.ctx = ESAPI()
                print("Connected to TPM via ESAPI with default TCTI")
                
            self.connected = True
            return True
        except Exception as e:
            print(f"Error connecting to TPM: {e}")
            self.connected = False
            return False

    def close(self):
        """Close the TPM connection."""
        if not TPM2_PYTSS_AVAILABLE or not self.connected:
            self.connected = False
            return
            
        try:
            if self.ctx:
                # In Python, the ESAPI object is cleaned up when it goes out of scope
                self.ctx = None
            self.connected = False
        except Exception as e:
            print(f"Error closing TPM connection: {e}")

    def extend_pcr(self, pcr_index: int, digest_hex: str) -> bool:
        """
        Extend a PCR with the given digest.
        
        Args:
            pcr_index: PCR index to extend
            digest_hex: Hex string of the digest to extend with
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not TPM2_PYTSS_AVAILABLE:
            print("TPM2_PYTSS not available, can't extend PCR")
            return False
            
        if not self.connected:
            print("Not connected to TPM")
            return False
            
        # Convert hex string to bytes
        try:
            digest_bytes = bytes.fromhex(digest_hex)
        except ValueError:
            print(f"Invalid hex digest: {digest_hex}")
            return False
            
        try:
            # Get the PCR handle using the direct ESYS_TR constants
            pcr_handles = {
                0: ESYS_TR.PCR0, 1: ESYS_TR.PCR1, 2: ESYS_TR.PCR2, 3: ESYS_TR.PCR3,
                4: ESYS_TR.PCR4, 5: ESYS_TR.PCR5, 6: ESYS_TR.PCR6, 7: ESYS_TR.PCR7,
                8: ESYS_TR.PCR8, 9: ESYS_TR.PCR9, 10: ESYS_TR.PCR10, 11: ESYS_TR.PCR11,
                12: ESYS_TR.PCR12, 13: ESYS_TR.PCR13, 14: ESYS_TR.PCR14, 15: ESYS_TR.PCR15,
                16: ESYS_TR.PCR16, 17: ESYS_TR.PCR17, 18: ESYS_TR.PCR18, 19: ESYS_TR.PCR19,
                20: ESYS_TR.PCR20, 21: ESYS_TR.PCR21, 22: ESYS_TR.PCR22, 23: ESYS_TR.PCR23
            }
            
            if pcr_index not in pcr_handles:
                print(f"Invalid PCR index: {pcr_index}")
                return False
                
            pcr_handle = pcr_handles[pcr_index]
            
            # Create digest structure based on the example
            digests = TPML_DIGEST_VALUES()
            sha256_digest = TPMT_HA(hashAlg=TPM2_ALG.SHA256)
            sha256_digest.digest.sha256 = digest_bytes
            
            # Add to digests list
            digests.count = 1
            digests[0] = sha256_digest
            
            # Extend the PCR
            self.ctx.pcr_extend(pcr_handle, digests)
            print(f"PCR {pcr_index} extended with digest: {digest_hex}")
            return True
        except Exception as e:
            print(f"Error extending PCR: {e}")
            return False

    def read_pcr(self, pcr_index: int) -> Optional[str]:
        """
        Read the current value of a PCR.
        
        Args:
            pcr_index: PCR index to read
        
        Returns:
            str: Hex string of the PCR value, or None if error
        """
        if not TPM2_PYTSS_AVAILABLE:
            print("TPM2_PYTSS not available, can't read PCR")
            return None
            
        if not self.connected:
            print("Not connected to TPM")
            return None
            
        try:
            # Create PCR selection for SHA256 and the specified PCR index
            # Format is "sha256:7" for PCR 7 with SHA256 algorithm
            pcr_select = TPML_PCR_SELECTION.parse(f"sha256:{pcr_index}")
            
            # Read the PCR value
            # Per documentation, pcr_read returns (update_counter, pcr_selection, pcr_values)
            _, _, pcr_values = self.ctx.pcr_read(pcr_select)
            
            # pcr_values is a TPML_DIGEST, which should contain the digest values
            # Directly access the digest if available
            if pcr_values and len(pcr_values.digests) > 0:
                # Return the first digest for this PCR
                return pcr_values.digests[0].buffer.hex()
            
            return None
        except Exception as e:
            print(f"Error reading PCR: {e}")
            return None

    def reset_pcr(self, pcr_index: int) -> bool:
        """
        Reset a resettable PCR.
        Note: Only PCRs 0-15 can typically be reset.
        
        Args:
            pcr_index: PCR index to reset
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not TPM2_PYTSS_AVAILABLE:
            print("TPM2_PYTSS not available, can't reset PCR")
            return False
            
        if not self.connected:
            print("Not connected to TPM")
            return False
            
        try:
            # Check if PCR is resettable
            if 16 <= pcr_index <= 23:
                print(f"PCR {pcr_index} is not resettable")
                return False
                
            # Reset the PCR
            # Convert PCR index to ESYS_TR handle using the same approach as extend_pcr
            pcr_handle = ESYS_TR(pcr_index)
            
            self.ctx.pcr_reset(pcr_handle)
            print(f"PCR {pcr_index} reset")
            return True
        except Exception as e:
            print(f"Error resetting PCR: {e}")
            return False 