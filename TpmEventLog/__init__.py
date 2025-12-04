"""
TPM Event Log Parser Package

This package provides tools for parsing TPM event logs, extracting PCR events
with their SHA-256 digests, and maintaining a database of events from multiple logs.
"""

__version__ = "1.1.0"

# Define the public API but don't import modules at package initialization time
# This avoids circular imports when running scripts directly

__all__ = [
    # Core models
    'EventLog', 'PcrEvent', 'DigestEntry',
    
    # Parsers
    'EventLogParser', 'TCGLogParser', 'TcgLog', 'TcgPcrEvent',
    
    # Database
    'EventLogDatabase', 'TcgLogAdapter', 'TcgDatabaseManager',
    
    # CLI entry points
    'yaml_parser_main', 'tcg_parser_main',
    
    # Utils
    'check_imports'
] 