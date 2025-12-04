"""
TPM Event Log Parser Database Module

This module contains database management functionality for storing and retrieving TPM event logs.
"""

# Don't import modules at initialization time to avoid import errors
# Define __all__ to indicate what should be imported with "from database import *"
__all__ = ['EventLogDatabase', 'TcgLogAdapter', 'TcgDatabaseManager']

__version__ = "1.1.0" 