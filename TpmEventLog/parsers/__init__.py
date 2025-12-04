"""
TPM Event Log Parser Parsers Module

This module contains different parser implementations for various TPM event log formats.
"""

# Don't import modules at initialization time to avoid import errors
# Define __all__ to indicate what should be imported with "from parsers import *"
__all__ = ['EventLogParser', 'TCGLogParser', 'TcgLog', 'TcgPcrEvent', 'parse_bitlocker_metadata']

__version__ = "1.1.0" 