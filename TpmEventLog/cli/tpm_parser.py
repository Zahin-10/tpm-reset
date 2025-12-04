#!/usr/bin/env python3
"""
TPM Event Log Parser Main Script

This script parses TPM event logs and adds them to a database of PCR events.
It serves as the main entry point for YAML format log parsing.

Usage:
    cd TpmEventLog
    python cli/tpm_parser.py log_file.yaml -d database.json [--store-raw-events]
    
Log files should be placed in the 'data' subdirectory. If only a filename is provided
(without a path), the script will look for the file in the 'data' directory.

Database files are stored in the 'db' subdirectory. If only a filename is provided
for the database file, it will be stored in the 'db' directory.

Note:
    Use --store-raw-events to include the full raw event data in the database.
    By default, only essential data like digests and event types are stored to keep the database size minimal.
"""

import argparse
import sys
import os

# Fix imports to work within the TpmEventLog directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsers.parser import EventLogParser
from database.database import EventLogDatabase


def main(args=None):
    """Main function to parse args and process the event log."""
    parser = argparse.ArgumentParser(
        description='Parse TPM event log and add to a database of PCR events.')
    parser.add_argument('log_file', help='Path to the TPM event log file (relative to data directory if no path provided)')
    parser.add_argument('--db', '-d', help='Path to the database JSON file (relative to db directory if no path provided)')
    parser.add_argument('--store-raw-events', action='store_true',
                       help='Store raw event data in the database (increases database size, disabled by default)')
    
    # Parse arguments from args if provided, otherwise from sys.argv
    if args:
        args = parser.parse_args(args)
    else:
        args = parser.parse_args()
    
    # Determine log file path - if only a filename is provided, look in the data directory
    log_file_path = args.log_file
    if not os.path.dirname(log_file_path):
        # Look in current directory first, then data directory
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        log_file_path = os.path.join(data_dir, log_file_path)
    
    # Check if file exists
    if not os.path.exists(log_file_path):
        print(f"Error: Log file '{log_file_path}' not found.")
        return 1
    
    # Determine database file path - if only a filename is provided, use the db directory
    db_file_path = args.db
    if db_file_path and not os.path.dirname(db_file_path):
        # Create db directory if it doesn't exist
        db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "db")
        os.makedirs(db_dir, exist_ok=True)
        db_file_path = os.path.join(db_dir, db_file_path)
    
    # Parse the log file
    event_log_parser = EventLogParser(log_file_path)
    event_log = event_log_parser.parse()
    
    # Add to database
    db = EventLogDatabase(db_file_path)
    log_id = db.add_event_log(event_log_parser, store_raw_events=args.store_raw_events)
    
    print(f"Parsed {len(event_log.events)} total events.")
    print(f"Found {len(event_log.sha256_events)} events with SHA-256 digests.")
    print(f"Added to database as log ID: {log_id}")
    print(f"Database saved to: {db.db_file_path}")
    print(f"Database now contains {len(db.get_source_ids())} sources and {len(db.get_pcr_indices())} PCR indices.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main()) 