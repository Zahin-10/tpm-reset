#!/usr/bin/env python3
"""
Test BitLocker Parser

This module contains tests for the BitLocker metadata parser.
"""

import os
import sys
import unittest
from unittest.mock import patch, mock_open

# Add the parent directory to the path so we can import the parsers module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.bitlocker_parser import (
    strip_info,
    extract_payload,
    parse_tpm2b_structure,
    extract_tpm_structures,
    parse_bitlocker_metadata
)


class TestBitLockerParser(unittest.TestCase):
    """Test cases for the BitLocker parser."""

    def test_strip_info(self):
        """Test the strip_info function."""
        input_line = "[INFO] 0x0000: 00-01-02-03-04-05-06-07"
        expected = "00 01 02 03 04 05 06 07"
        self.assertEqual(strip_info(input_line), expected)

    def test_parse_tpm2b_structure(self):
        """Test the parse_tpm2b_structure function."""
        # Create a simple TPM2B structure with size 4 and data 0x01020304
        data = bytes.fromhex("0004 01020304")
        structure, offset = parse_tpm2b_structure(data, 0)
        self.assertEqual(structure, data)
        self.assertEqual(offset, 6)  # 2 bytes for size + 4 bytes for data

    def test_extract_tpm_structures(self):
        """Test the extract_tpm_structures function."""
        # Create two TPM2B structures
        data = bytes.fromhex("0004 01020304 0003 050607")
        structures = extract_tpm_structures(data)
        self.assertIn('TPM2B_PRIVATE', structures)
        self.assertIn('TPM2B_PUBLIC', structures)
        self.assertEqual(structures['TPM2B_PRIVATE'], bytes.fromhex("0004 01020304"))
        self.assertEqual(structures['TPM2B_PUBLIC'], bytes.fromhex("0003 050607"))

    @patch('builtins.open', new_callable=mock_open, read_data="[INFO] ENTRY TYPE VMK\n[INFO] UTF-16 string: 'TPM Protection'\n" + "\n" * 24 + "[INFO] 0x0000: 00-04-01-02-03-04-00-03-05-06-07\n[INFO] ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    def test_extract_payload(self, mock_file):
        """Test the extract_payload function."""
        with open('dummy_file.txt', 'r') as f:
            trace = f.read()
        payload = extract_payload(trace)
        self.assertEqual(payload, "000401020304000305060708")

    @patch('parsers.bitlocker_parser.extract_payload', return_value="000401020304000305060708")
    @patch('parsers.bitlocker_parser.save_binary_data')
    @patch('os.makedirs')
    def test_parse_bitlocker_metadata(self, mock_makedirs, mock_save, mock_extract):
        """Test the parse_bitlocker_metadata function."""
        with patch('builtins.open', mock_open(read_data="dummy data")):
            structures = parse_bitlocker_metadata('dummy_file.txt', 'output_dir')
        
        self.assertIn('TPM2B_PRIVATE', structures)
        self.assertIn('TPM2B_PUBLIC', structures)
        mock_makedirs.assert_called_once_with('output_dir', exist_ok=True)
        self.assertEqual(mock_save.call_count, 2)


if __name__ == '__main__':
    unittest.main() 