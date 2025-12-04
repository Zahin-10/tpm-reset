#!/usr/bin/env python3
"""
Standalone TCG Log Parser Script

This script allows you to run the TCG JSON parser independently while still updating
the same database as the YAML parser. It parses a TCG JSON log file and adds it to
the database using the TCG database adapter.

Usage:
    cd TpmEventLog
    python cli/run_tcg_parser.py [tcg_log_file] [--db DB_FILE] [--verbose] [--store-raw-events]

Example:
    python cli/run_tcg_parser.py data/TCGlog_SRTMCurrent.json
    python cli/run_tcg_parser.py data/TCGlog_SRTMCurrent.json --db custom_database.json
    
Note:
    Use --store-raw-events to include the full raw event data in the database.
    By default, only essential data like digests and event types are stored to keep the database size minimal.
"""

import os
import sys
import argparse
import logging

# Fix imports to work within the TpmEventLog directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from parsers.tcg_parser import TCGLogParser
from database.tcg_database_adapter import TcgDatabaseManager


def setup_logging(verbose=False):
    """Set up logging configuration"""
    log_level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def main(args=None):
    """Main function to run the TCG parser"""
    parser = argparse.ArgumentParser(
        description='Parse TCG JSON log file and add it to the TPM database')
    parser.add_argument('tcg_log', nargs='?',
                       help='Path to the TCG JSON log file')
    parser.add_argument('--db', help='Path to the database file')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--store-raw-events', action='store_true',
                       help='Store raw event data in the database (increases database size, disabled by default)')
    
    # Parse arguments from args if provided, otherwise from sys.argv
    if args:
        parsed_args = parser.parse_args(args)
    else:
        parsed_args = parser.parse_args()
    
    # Set up logging
    setup_logging(parsed_args.verbose)
    
    # Default log file if not specified
    tcg_log_path = parsed_args.tcg_log
    if not tcg_log_path:
        # Use a default log file in the data directory
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        tcg_log_path = os.path.join(data_dir, "TCGlog_SRTMCurrent.json")
        print(f"No log file specified, using default: {tcg_log_path}")
    
    # Handle relative paths in data directory
    if not os.path.exists(tcg_log_path) and not os.path.dirname(tcg_log_path):
        data_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
        tcg_log_path = os.path.join(data_dir, tcg_log_path)
    
    if not os.path.exists(tcg_log_path):
        print(f"Error: TCG log file not found: {tcg_log_path}")
        return 1
    
    print(f"Processing TCG log: {tcg_log_path}")
    
    # Determine database file path
    db_file_path = parsed_args.db
    if db_file_path and not os.path.dirname(db_file_path):
        # Create db directory if it doesn't exist
        db_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "db")
        os.makedirs(db_dir, exist_ok=True)
        db_file_path = os.path.join(db_dir, db_file_path)
    
    # Parse the TCG log
    try:
        parser = TCGLogParser(tcg_log_path, verbose=parsed_args.verbose)
        tcg_log = parser.parse()
        
        # Print summary
        parser.print_events_summary()
        
        # Add to database using the adapter
        db_manager = TcgDatabaseManager(db_file_path)
        log_id = db_manager.add_tcg_log(parser, store_raw_events=parsed_args.store_raw_events)
        
        print(f"\nAdded TCG log to database with ID: {log_id}")
        print(f"Database file: {db_manager.database.db_file_path}")
        
        return 0
    except Exception as e:
        print(f"Error processing TCG log: {e}")
        if parsed_args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main()) 