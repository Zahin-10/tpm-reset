#!/usr/bin/env python3
"""
BitLocker Metadata Parser CLI

This script provides a command-line interface for parsing BitLocker metadata
and extracting TPM-related structures from it.

Usage:
    python bitlocker_parser_cli.py [metadata_file] [--output-dir OUTPUT_DIR]
    
Example:
    python bitlocker_parser_cli.py metadata-secboot --output-dir output/metadata
"""

import os
import sys
import argparse
from pathlib import Path

# Add the parent directory to the path so we can import the parsers module
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.bitlocker_parser import parse_bitlocker_metadata


def main():
    """Main entry point for the BitLocker metadata parser CLI."""
    parser = argparse.ArgumentParser(
        description='Parse BitLocker metadata and extract TPM structures',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python bitlocker_parser_cli.py metadata-secboot
  python bitlocker_parser_cli.py metadata-secboot --output-dir output/metadata"""
    )
    
    parser.add_argument('metadata_file', help='Name of the BitLocker metadata file (in data/metadata directory)')
    parser.add_argument('--output-dir', '-o', default='output/metadata',
                      help='Directory to save extracted structures (default: output/metadata)')
    
    args = parser.parse_args()
    
    # Create the output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Construct the full path to the metadata file
    metadata_path = os.path.join('data', 'metadata', args.metadata_file)
    
    print(f"Parsing BitLocker metadata from {metadata_path}...")
    structures = parse_bitlocker_metadata(metadata_path, args.output_dir)
    
    if not structures:
        print("Failed to extract TPM structures from BitLocker metadata.")
        return 1
    
    print("\nExtracted TPM structures:")
    for name, data in structures.items():
        print(f"  - {name}: {len(data)} bytes")
    
    print(f"\nStructures saved to {args.output_dir}/")
    return 0


if __name__ == '__main__':
    sys.exit(main()) 