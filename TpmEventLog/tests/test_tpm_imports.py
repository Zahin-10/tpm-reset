#!/usr/bin/env python3

"""
Unit tests for TPM2_PYTSS imports and TPM module functionality.

These tests verify that the required TPM modules can be imported correctly
and basic functionality works as expected.
"""

import os
import sys
import unittest
from unittest import mock
import platform

# Add the parent directory to the path to ensure we can import TpmEventLog modules
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)


class TestTpm2PyTssImports(unittest.TestCase):
    """Test cases for tpm2_pytss imports and TPM module functionality."""

    def setUp(self):
        """Set up test environment."""
        # Print system information for debugging
        print(f"\nRunning tests on Python {platform.python_version()}")
        print(f"Python executable: {sys.executable}")
        print(f"System platform: {platform.platform()}")

    def test_tpm2_pytss_basic_import(self):
        """Test basic import of tpm2_pytss module."""
        try:
            import tpm2_pytss
            self.assertIsNotNone(tpm2_pytss, "tpm2_pytss module should be imported")
            print(f"tpm2_pytss path: {tpm2_pytss.__file__}")
            # Try to get the version if available
            version = getattr(tpm2_pytss, "__version__", "unknown")
            print(f"tpm2_pytss version: {version}")
        except ImportError as e:
            self.fail(f"Failed to import tpm2_pytss: {e}")

    def test_tpm2_pytss_specific_imports(self):
        """Test import of specific classes from tpm2_pytss."""
        try:
            from tpm2_pytss import ESAPI, ESYS_TR, TPM2B_NONCE, TPMT_SYM_DEF, TPML_PCR_SELECTION
            # If we reach here, the import was successful
            self.assertTrue(True, "Successfully imported specific classes from tpm2_pytss")
        except ImportError as e:
            self.fail(f"Failed to import specific classes from tpm2_pytss: {e}")

    def test_esapi_interface_import(self):
        """Test import of ESAPIInterface from tpm.esapi_interface."""
        try:
            from tpm.esapi_interface import ESAPIInterface, TPM2_PYTSS_AVAILABLE
            self.assertIsNotNone(ESAPIInterface, "ESAPIInterface class should be imported")
            
            # Print whether tpm2_pytss is available
            print(f"TPM2_PYTSS_AVAILABLE: {TPM2_PYTSS_AVAILABLE}")
            
            # If TPM2_PYTSS_AVAILABLE is False, we should skip tests that require it
            if not TPM2_PYTSS_AVAILABLE:
                print("Warning: tpm2_pytss is not available, some functionality will be limited")
                
            # Create an instance to check basic functionality
            esapi = ESAPIInterface()
            self.assertIsNotNone(esapi, "Should be able to create ESAPIInterface instance")
            
            # Check if key methods exist
            self.assertTrue(hasattr(esapi, "connect"), "ESAPIInterface should have connect method")
            self.assertTrue(hasattr(esapi, "close"), "ESAPIInterface should have close method")
            self.assertTrue(hasattr(esapi, "extend_pcr"), "ESAPIInterface should have extend_pcr method")
            self.assertTrue(hasattr(esapi, "read_pcr"), "ESAPIInterface should have read_pcr method")
            self.assertTrue(hasattr(esapi, "reset_pcr"), "ESAPIInterface should have reset_pcr method")
            
        except ImportError as e:
            self.fail(f"Failed to import ESAPIInterface from tpm.esapi_interface: {e}")

    def test_pcr_extend_import(self):
        """Test import of pcr_extend module."""
        try:
            # Add cli directory to path if needed
            cli_dir = os.path.join(parent_dir, 'cli')
            if cli_dir not in sys.path:
                sys.path.append(cli_dir)
                
            from pcr_extend import main as extend_main
            self.assertIsNotNone(extend_main, "extend_main function should be imported")
        except ImportError as e:
            self.fail(f"Failed to import pcr_extend module: {e}")


if __name__ == '__main__':
    unittest.main() 