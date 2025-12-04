#!/usr/bin/env python3
"""
TPM Event Log Summary Generator

This script provides a command-line interface to generate a detailed summary
of a single TPM event log source for a specific PCR.

Usage:
    cd TpmEventLog
    python cli/summary.py --db DB_FILE --pcr PCR_INDEX
    
Example:
    python cli/summary.py --db db/logs.json --pcr 7
"""

import sys
import os
import argparse
import json
from tabulate import tabulate
from typing import Dict, Any, List, Optional
import hashlib

# Fix imports to work within the TpmEventLog directory
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database.database import EventLogDatabase
from cli.analyse import get_event_type, get_sha256_digest, calculate_pcr_extend


def generate_source_summary(db, pcr_index, source_id):
    """
    Generate a detailed summary report for a single source and specific PCR index.
    Shows all PCR extension digests chronologically and the final calculated PCR value.
    Automatically saves the summary results to a JSON file.
    
    Args:
        db: The event log database
        pcr_index: The PCR index to summarize
        source_id: Source ID
    """
    # Get source information
    source = db.get_source_by_id(source_id)
    
    if not source:
        print(f"Error: Source {source_id} not found.")
        return
    
    # Get readable source name
    source_name = source.get('name', source.get('source_file', source_id))
    
    print(f"\nPCR {pcr_index} Event Log Summary:")
    print(f"Source: {source_name}")
    print(f"ID: {source_id}")
    print(f"File: {source.get('source_file', 'N/A')}")
    
    # Get all events for the specified PCR from the source in chronological order
    events = db.get_events_by_source_and_pcr(source_id, pcr_index)
    
    # Get final calculated PCR value
    pcr_index_str = str(pcr_index)
    final_pcr = "N/A"
    
    if (pcr_index_str in db.database['pcrs'] and 
        'summary' in db.database['pcrs'][pcr_index_str]):
        summary = db.database['pcrs'][pcr_index_str]['summary']
        if source_id in summary:
            final_pcr = summary[source_id].get('calculated_value', 'N/A')
            if final_pcr != "N/A":
                final_pcr = final_pcr.lower()
    
    # Count event types
    event_type_count = {}
    for event in events:
        event_type = get_event_type(event)
        if event_type in event_type_count:
            event_type_count[event_type] += 1
        else:
            event_type_count[event_type] = 1
    
    # Prepare data for tabulate and JSON output
    table_data = []
    json_data = {
        "summary_info": {
            "pcr_index": pcr_index,
            "source": {
                "id": source_id,
                "name": source_name,
                "file": source.get('source_file', 'N/A'),
                "final_pcr_value": final_pcr
            },
            "event_summary": {
                "total_events": len(events),
                "event_types": event_type_count
            }
        },
        "events": []
    }
    
    running_digest = "0" * 64  # Starting PCR value is all zeros
    
    # Process all events
    for i, event in enumerate(events):
        row = []
        event_type = get_event_type(event)
        event_num = event.get('event_number', event.get('event_num', 'N/A'))
        
        # Position in sequence (1-indexed for display)
        position = i + 1
        row.append(position)
        row.append(event_num)
        row.append(event_type)
        
        # Get SHA-256 digest
        sha256_digest = None
        if 'sha256_digest' in event:
            sha256_digest = event['sha256_digest']
            if sha256_digest:
                sha256_digest = sha256_digest.lower()
        elif 'digests' in event and 'sha256' in event['digests']:
            sha256_digest = event['digests']['sha256']
            if sha256_digest:
                sha256_digest = sha256_digest.lower()
        
        if sha256_digest:
            # Update running digest
            if running_digest != "Error":
                running_digest = calculate_pcr_extend(running_digest, sha256_digest)
            
            # Show full SHA-256 digest
            row.append(sha256_digest)
            
            # Also show the running PCR value after this extend
            row.append(running_digest)
        else:
            row.append("N/A")
            row.append("N/A")
            running_digest = "Error"
        
        table_data.append(row)
        
        # Add event to JSON
        event_json = {
            "position": position,
            "event_number": event_num,
            "event_type": event_type,
            "extend_digest": sha256_digest if sha256_digest else "N/A",
            "pcr_value": running_digest,
            "data": {}
        }
        
        # Add additional event data if available
        if 'event_data' in event:
            event_json["data"]["event_data"] = event['event_data']
        if 'efi_variable_data' in event:
            event_json["data"]["efi_variable_data"] = event['efi_variable_data']
        if 'event_size' in event:
            event_json["data"]["event_size"] = event['event_size']
        
        json_data["events"].append(event_json)
    
    # Add final calculated PCR value as the last row
    final_row = ["FINAL", "", "Final PCR", "", final_pcr]
    table_data.append(final_row)
    
    # Display the summary table
    headers = ["Pos", "Event #", "Event Type", "Extend Digest", "PCR Value"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Summary information
    print(f"\nTotal events: {len(events)}")
    print("\nEvent type distribution:")
    for event_type, count in event_type_count.items():
        print(f"  {event_type}: {count}")
    print(f"\nFinal PCR value: {final_pcr}")
    
    # Automatically save to JSON file
    json_output_file = f"pcr{pcr_index}_source_{source_id[:8]}_summary.json"
    try:
        # Create output directory if it doesn't exist
        os.makedirs("output", exist_ok=True)
        json_output_path = os.path.join("output", json_output_file)
        with open(json_output_path, 'w') as f:
            json.dump(json_data, f, indent=2)
        print(f"\nSummary saved to {json_output_path}")
    except Exception as e:
        print(f"\nError saving summary to JSON file: {e}")
    
    return json_data


def interactive_source_selection(db):
    """
    Prompt the user to select a source from the available sources in the database.
    
    Args:
        db: The event log database
        
    Returns:
        The selected source ID or None if canceled
    """
    sources = db.get_source_ids()
    
    if not sources:
        print("No sources found in the database.")
        return None
    
    print("\nAvailable sources:")
    for i, source_id in enumerate(sources):
        source = db.get_source_by_id(source_id)
        source_name = source.get('name', source.get('source_file', source_id))
        print(f"{i+1}. {source_name} [{source_id}]")
    
    while True:
        try:
            choice = input("\nEnter the number of the source to summarize (or 'q' to quit): ")
            if choice.lower() == 'q':
                return None
            
            choice_num = int(choice)
            if 1 <= choice_num <= len(sources):
                return sources[choice_num - 1]
            else:
                print(f"Please enter a number between 1 and {len(sources)}.")
        except ValueError:
            print("Please enter a valid number or 'q' to quit.")


def main():
    """
    Main entry point for the summary tool.
    """
    parser = argparse.ArgumentParser(description='TPM Event Log Summary Generator')
    parser.add_argument('--db', type=str, required=True, help='Path to the database file')
    parser.add_argument('--pcr', type=int, default=7, help='PCR index to summarize')
    parser.add_argument('--source', type=str, help='Source ID to generate summary for (skips interactive selection)')
    
    args = parser.parse_args()
    
    # Load the database
    db = EventLogDatabase(args.db)
    
    # Interactive source selection
    selected_source = None
    if args.source:
        # Check if the provided source ID exists
        if args.source in db.get_source_ids():
            selected_source = args.source
            print(f"Using specified source ID: {selected_source}")
        else:
            print(f"Error: Provided source ID '{args.source}' not found in the database.")
            # List available sources for user convenience if given an invalid one
            sources = db.get_source_ids()
            if sources:
                print("Available source IDs:")
                for sid in sources:
                    s_details = db.get_source_by_id(sid)
                    s_name = s_details.get('name', s_details.get('source_file', sid))
                    print(f"  - {s_name} [{sid}]")
            else:
                print("No sources found in the database.")
            sys.exit(1) # Exit if invalid source_id is provided non-interactively
    else:
        selected_source = interactive_source_selection(db)
    
    if selected_source:
        generate_source_summary(db, args.pcr, selected_source)
    else:
        print("Summary generation canceled.")


if __name__ == '__main__':
    main() 