#!/usr/bin/env python3

"""
Test runner for TpmEventLog unit tests.

This script discovers and runs all the test cases in the tests directory.
To run a specific test or test case, pass it as an argument:
    python run_tests.py test_tpm_imports.TestTpm2PyTssImports.test_tpm2_pytss_basic_import
"""

import os
import sys
import unittest
import argparse


def main():
    """Discover and run tests."""
    # Add the parent directory to the path to ensure we can import TpmEventLog modules
    parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    if parent_dir not in sys.path:
        sys.path.append(parent_dir)

    parser = argparse.ArgumentParser(description='Run TpmEventLog unit tests')
    parser.add_argument('test_path', nargs='?', default=None,
                        help='Specific test to run (e.g., test_tpm_imports.TestTpm2PyTssImports)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output')
    args = parser.parse_args()

    # Set verbosity level
    verbosity = 2 if args.verbose else 1

    if args.test_path:
        # Run specific test
        print(f"Running specific test: {args.test_path}")
        suite = unittest.TestLoader().loadTestsFromName(args.test_path, module=None)
    else:
        # Discover and run all tests
        print("Discovering and running all tests...")
        start_dir = os.path.dirname(os.path.abspath(__file__))
        suite = unittest.TestLoader().discover(start_dir, pattern='test_*.py')

    # Run the tests
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    
    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main()) 