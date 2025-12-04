#!/usr/bin/env python3
"""
TPM Event Log Analysis Tool

This script provides a command-line interface to query, analyze, and compare
TPM event logs stored in the database.

Usage:
    cd TpmEventLog
    python cli/analyse.py --pcr PCR_INDEX [--db DB_FILE] [--source1 SOURCE_ID] [--source2 SOURCE_ID]
    
Example:
    python cli/analyse.py --pcr 0 --source1 123e4567-e89b-12d3-a456-426614174000
"""

import os
import sys
import json
import hashlib
import argparse
from typing import Dict, List, Any, Optional, Tuple
from tabulate import tabulate

# Calculate PCR extend function, moved from utils.utils
def calculate_pcr_extend(initial_value: str, measurement: str) -> str:
    """
    Calculate the PCR extend operation: PCR_new = SHA256(PCR_old || measurement).
    
    Args:
        initial_value: Initial PCR value as a hex string
        measurement: Measurement to extend with as a hex string
        
    Returns:
        The new PCR value as a hex string
    """
    try:
        initial_bytes = bytes.fromhex(initial_value.lower())
        measurement_bytes = bytes.fromhex(measurement.lower())
        
        # Calculate new PCR value
        sha256 = hashlib.sha256()
        sha256.update(initial_bytes)
        sha256.update(measurement_bytes)
        
        # Return new PCR value as hex string
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error recalculating PCR: {e}")
        return "Error"

# Local imports
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from database.database import EventLogDatabase

# Constants
TERMINAL_WIDTH = 120
TRUNCATE_LENGTH = 40  # Length to truncate long strings


def format_event_summary(event: Dict[str, Any]) -> str:
    """Format an event for display"""
    # Format event based on available data
    event_num = event.get('event_num', 'Unknown')
    source_id = event.get('source_id', 'Unknown')
    sha256 = event.get('sha256_digest', '')[:8] + '...' if event.get('sha256_digest') else 'No SHA-256'
    
    # Try to get a meaningful name from the event data
    event_data = event.get('event_data', {})
    event_name = (
        event_data.get('EventName', '') or 
        event_data.get('event_type', '') or 
        (event_data.get('Event', {}) or {}).get('String', '') or
        'Unknown'
    )
    
    return f"Event {event_num}, Source: {source_id[:8]}..., SHA-256: {sha256}, Data: {event_name}"


def display_events_by_type(db: EventLogDatabase, pcr_index: int, event_type: str, 
                       source_id: Optional[str] = None) -> None:
    """
    Display all events of a specific type for a PCR.
    
    Args:
        db: The event log database
        pcr_index: PCR index to filter by
        event_type: Event type to filter by
        source_id: Optional source ID to filter by
    """
    # Get all events for the specified PCR
    pcr_str = str(pcr_index)
    if pcr_str not in db.database['pcrs']:
        print(f"PCR {pcr_index} not found in database.")
        return
    
    # Filter events by type
    matching_events = []
    
    # Check if the events are stored by source or chronologically
    if 'events' in db.database['pcrs'][pcr_str]:
        for event_num, event_data in db.database['pcrs'][pcr_str]['events'].items():
            # Check if the event matches the specified type
            if 'sources' in event_data:
                for src_id, src_data in event_data['sources'].items():
                    if (source_id is None or src_id == source_id) and src_data.get('event_type') == event_type:
                        matching_events.append({
                            'event_num': event_num,
                            'source_id': src_id,
                            'source_name': db.get_source_name(src_id),
                            'sha256_digest': src_data.get('sha256_digest', 'N/A'),
                            'event_data': src_data.get('event_data', {})
                        })
    
    # Sort by event number
    matching_events.sort(key=lambda x: int(x['event_num']) if x['event_num'].isdigit() else float('inf'))
    
    if not matching_events:
        print(f"No events found for PCR {pcr_index} with type '{event_type}'")
        return
    
    print(f"\nEvents of type '{event_type}' for PCR {pcr_index}:")
    if source_id:
        print(f"Source: {db.get_source_name(source_id)} ({source_id})")
    
    for event in matching_events:
        print(format_event_summary(event))


def get_event_type(event: Dict[str, Any]) -> Optional[str]:
    """
    Extract the event type from an event.
    
    Args:
        event: The event data
        
    Returns:
        The event type as a string, or None if not found
    """
    # Direct event_type field
    if 'event_type' in event:
        return event['event_type']
    
    # Look for event type in event_data
    event_data = event.get('event_data', {})
    if 'EventType' in event_data:
        return event_data['EventType']
    elif 'event_type' in event_data:
        return event_data['event_type']
    elif 'EventName' in event_data:
        return event_data['EventName']
    
    # Look in TCG format
    tcg_event = event_data.get('Event', {})
    if isinstance(tcg_event, dict) and 'EventType' in tcg_event:
        return tcg_event['EventType']
    
    return None


def list_sources(db: EventLogDatabase) -> List[str]:
    """
    List all sources in the database.
    
    Args:
        db: The event log database
        
    Returns:
        List of source IDs
    """
    if 'sources' not in db.database:
        print("No sources found in database.")
        return []
    
    source_ids = []
    print("\nAvailable sources:")
    for i, (source_id, source_data) in enumerate(db.database['sources'].items(), 1):
        source_name = source_data.get('name', 'Unknown')
        source_file = source_data.get('source_file', 'N/A')
        event_count = source_data.get('event_count', 0)
        
        print(f"{i}. ID: {source_id}")
        print(f"   Name: {source_name}")
        print(f"   File: {source_file}")
        print(f"   Events: {event_count}")
        
        source_ids.append(source_id)
    
    return source_ids


def list_pcrs(db: EventLogDatabase) -> None:
    """
    List all PCR indices found in the database.
    
    Args:
        db: The event log database
    """
    if 'pcrs' not in db.database:
        print("No PCRs found in database.")
        return
    
    pcr_indices = sorted(int(idx) for idx in db.database['pcrs'].keys() if idx.isdigit())
    
    if not pcr_indices:
        print("No PCR indices found in database.")
        return
    
    print("\nAvailable PCR indices:")
    table_data = []
    
    for pcr_idx in pcr_indices:
        pcr_str = str(pcr_idx)
        pcr_data = db.database['pcrs'][pcr_str]
        
        event_count = 0
        source_count = 0
        
        # Count events based on available data structure
        if 'events' in pcr_data:
            event_count = len(pcr_data['events'])
            
            # Count unique sources that have events for this PCR
            unique_sources = set()
            for event_data in pcr_data['events'].values():
                if 'sources' in event_data:
                    unique_sources.update(event_data['sources'].keys())
            source_count = len(unique_sources)
        
        table_data.append([
            pcr_idx,
            event_count,
            source_count
        ])
    
    headers = ["PCR Index", "Event Count", "Source Count"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def list_event_types(db: EventLogDatabase, pcr_index: int) -> None:
    """
    List all event types found for a specific PCR index.
    
    Args:
        db: The event log database
        pcr_index: The PCR index to list event types for
    """
    pcr_str = str(pcr_index)
    if pcr_str not in db.database['pcrs']:
        print(f"PCR {pcr_index} not found in database.")
        return
    
    pcr_data = db.database['pcrs'][pcr_str]
    
    # Extract event types
    event_types = {}
    
    # Process the events based on available data structure
    if 'events' in pcr_data:
        for event_data in pcr_data['events'].values():
            if 'sources' in event_data:
                for source_id, source_data in event_data['sources'].items():
                    event_type = source_data.get('event_type')
                    if event_type:
                        if event_type not in event_types:
                            event_types[event_type] = {'event_count': 0, 'sources': set()}
                        event_types[event_type]['event_count'] += 1
                        event_types[event_type]['sources'].add(source_id)
    
    if not event_types:
        print(f"No event types found for PCR {pcr_index}.")
        return
    
    print(f"\nEvent types for PCR {pcr_index}:")
    table_data = []
    
    for event_type, counts in event_types.items():
        table_data.append([
            event_type,
            counts['event_count'],
            len(counts['sources'])
        ])
    
    # Sort by event count (descending)
    table_data.sort(key=lambda x: x[1], reverse=True)
    
    headers = ["Event Type", "Event Count", "Source Count"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def inspect_event_structures(db: EventLogDatabase, pcr_index: int, source_id: str, limit: int = 3) -> None:
    """
    Inspect the structure of events for a specific PCR and source.
    
    Args:
        db: The event log database
        pcr_index: The PCR index to inspect
        source_id: The source ID to inspect
        limit: Maximum number of events to display
    """
    events = db.get_events_by_source_and_pcr(source_id, pcr_index)
    
    if not events:
        print(f"No events found for PCR {pcr_index} from source {source_id}.")
        return
    
    source_name = db.get_source_name(source_id)
    
    print(f"\nEvent structure inspection for PCR {pcr_index}, Source: {source_name} ({source_id}):")
    print(f"Showing first {min(limit, len(events))} events:")
    
    for i, event in enumerate(events[:limit], 1):
        print(f"\nEvent {i}/{min(limit, len(events))}:")
        event_type = get_event_type(event)
        print(f"  Event Type: {event_type}")
        
        # Print SHA-256 digest if available
        if 'sha256_digest' in event:
            print(f"  SHA-256: {event['sha256_digest']}")
        elif 'digests' in event and 'sha256' in event['digests']:
            print(f"  SHA-256: {event['digests']['sha256']}")
        
        # Print key structure info
        print("  Structure:")
        for key, value in event.items():
            if key == 'event_data' or key == 'digests':
                continue  # Skip details for now
            print(f"    {key}: {value}")
        
        # Print detailed event data structure if available
        if 'event_data' in event and event['event_data']:
            print("  Event Data Keys:")
            for key in event['event_data'].keys():
                print(f"    - {key}")


def analyze_event_types(db: EventLogDatabase, pcr_index: int, source_id: str) -> None:
    """
    Analyze event types for a specific PCR and source.
    
    Args:
        db: The event log database
        pcr_index: The PCR index to analyze
        source_id: The source ID to analyze
    """
    events = db.get_events_by_source_and_pcr(source_id, pcr_index)
    
    if not events:
        print(f"No events found for PCR {pcr_index} from source {source_id}.")
        return
    
    source_name = db.get_source_name(source_id)
    
    print(f"\nEvent type analysis for PCR {pcr_index}, Source: {source_name} ({source_id}):")
    print(f"Total events: {len(events)}")
    
    # Extract event types
    extracted_types = []
    for event in events:
        event_type = get_event_type(event)
        if event_type:
            extracted_types.append(event_type)
    
    # Count unique event types
    unique_types = set(extracted_types)
    print(f"Unique event types: {len(unique_types)}")
    
    # Print counts for each event type
    print("Event type distribution:")
    for event_type in sorted(unique_types):
        count = extracted_types.count(event_type)
        print(f"  - {event_type}: {count} events")


def display_pcr_values(db, pcr_index):
    """
    Display the calculated PCR values for all sources for a specific PCR index.
    
    Args:
        db: The event log database
        pcr_index: The PCR index to show values for
    """
    all_sources = db.get_source_ids()
    
    if not all_sources:
        print("No sources found in the database.")
        return
    
    print(f"\nCalculated PCR {pcr_index} Values:")
    
    table_data = []
    for source_id in all_sources:
        source = db.get_source_by_id(source_id)
        source_name = source.get('name', 'Unknown')
        source_file = source.get('source_file', 'N/A')
        
        # Get all events for this PCR index
        events = db.get_events_by_source_and_pcr(source_id, pcr_index)
        
        # Calculate the PCR value based on all extension events
        pcr_value = "0000000000000000000000000000000000000000000000000000000000000000"  # Initial PCR value
        for event in events:
            # Get the SHA-256 digest from the event
            sha256_digest = get_sha256_digest(event)
            if sha256_digest:
                pcr_value = calculate_pcr_extend(pcr_value, sha256_digest)
        
        table_data.append([
            source_id,
            source_name,
            source_file,
            len(events),
            pcr_value
        ])
    
    # Sort by source name
    table_data.sort(key=lambda x: x[1])
    
    headers = ["Source ID", "Source Name", "Source File", "Event Count", "Calculated PCR Value"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def compare_sources(db, pcr_index, source_id1, source_id2):
    """
    Perform a side-by-side comparison of events from two sources.
    Shows all PCR extension digests chronologically and the final calculated PCR value.
    
    Args:
        db: The event log database
        pcr_index: The PCR index to compare
        source_id1: First source ID
        source_id2: Second source ID
    """
    # Get source information
    source1 = db.get_source_by_id(source_id1)
    source2 = db.get_source_by_id(source_id2)
    
    if not source1 or not source2:
        print("Error: One or both sources not found.")
        return
    
    # Get readable source names
    source1_name = source1.get('name', source1.get('source_file', source_id1))
    source2_name = source2.get('name', source2.get('source_file', source_id2))
    
    print(f"\nChronological PCR {pcr_index} Extend Operations Comparison:")
    print(f"Source 1: {source1_name}")
    print(f"         ID: {source_id1}")
    print(f"         File: {source1.get('source_file', 'N/A')}")
    print(f"Source 2: {source2_name}")
    print(f"         ID: {source_id2}")
    print(f"         File: {source2.get('source_file', 'N/A')}")
    
    # Get all events for the specified PCR from both sources in chronological order
    events1 = db.get_events_by_source_and_pcr(source_id1, pcr_index)
    events2 = db.get_events_by_source_and_pcr(source_id2, pcr_index)
    
    # Get final calculated PCR values
    pcr_index_str = str(pcr_index)
    final_pcr1 = "N/A"
    final_pcr2 = "N/A"
    
    if (pcr_index_str in db.database['pcrs'] and 
        'summary' in db.database['pcrs'][pcr_index_str]):
        summary = db.database['pcrs'][pcr_index_str]['summary']
        if source_id1 in summary:
            final_pcr1 = summary[source_id1].get('calculated_value', 'N/A')
            if final_pcr1 != "N/A":
                final_pcr1 = final_pcr1.lower()
        if source_id2 in summary:
            final_pcr2 = summary[source_id2].get('calculated_value', 'N/A')
            if final_pcr2 != "N/A":
                final_pcr2 = final_pcr2.lower()
                
    # Check if final PCR values match (case-insensitive)
    final_pcr_match = (final_pcr1 != "N/A" and final_pcr2 != "N/A" and final_pcr1.lower() == final_pcr2.lower())
    
    # Prepare data for tabulate and JSON output
    table_data = []
    match_count = 0
    total_comparisons = 0
    
    # Track digests and matches for more detailed analysis
    digest_matches = []
    
    running_digest1 = "0" * 64  # Starting PCR value is all zeros
    running_digest2 = "0" * 64  # Starting PCR value is all zeros
    
    # Get the maximum number of events between the two sources
    max_events = max(len(events1), len(events2))
    
    # Process events first to collect match data before building the JSON
    for i in range(max_events):
        row = []
        row.append(i + 1)  # Position in sequence (1-indexed for display)
        
        # Source 1 data
        event1 = None
        sha256_1 = None
        if i < len(events1):
            event1 = events1[i]
            event_type1 = get_event_type(event1)
            event_num1 = event1.get('event_number', event1.get('event_num', 'N/A'))
            row.append(event_num1)
            row.append(event_type1)
            
            # Get SHA-256 digest
            if 'sha256_digest' in event1:
                sha256_1 = event1['sha256_digest']
                if sha256_1:
                    sha256_1 = sha256_1.lower()
            elif 'digests' in event1 and 'sha256' in event1['digests']:
                sha256_1 = event1['digests']['sha256']
                if sha256_1:
                    sha256_1 = sha256_1.lower()
                
            if sha256_1:
                # Update running digest for source 1
                if running_digest1 != "Error":
                    running_digest1 = calculate_pcr_extend(running_digest1, sha256_1)
                
                # Show full SHA-256 digest
                row.append(sha256_1)
                
                # Also show the running PCR value after this extend
                row.append(running_digest1)
            else:
                row.append("N/A")
                row.append("N/A")
                running_digest1 = "Error"
        else:
            # Placeholders for empty source 1 data
            row.extend(["N/A", "N/A", "N/A", "N/A"])
            
        # Source 2 data
        event2 = None
        sha256_2 = None
        if i < len(events2):
            event2 = events2[i]
            event_type2 = get_event_type(event2)
            event_num2 = event2.get('event_number', event2.get('event_num', 'N/A'))
            row.append(event_num2)
            row.append(event_type2)
            
            # Get SHA-256 digest
            if 'sha256_digest' in event2:
                sha256_2 = event2['sha256_digest']
                if sha256_2:
                    sha256_2 = sha256_2.lower()
            elif 'digests' in event2 and 'sha256' in event2['digests']:
                sha256_2 = event2['digests']['sha256']
                if sha256_2:
                    sha256_2 = sha256_2.lower()
                
            if sha256_2:
                # Update running digest for source 2
                if running_digest2 != "Error":
                    running_digest2 = calculate_pcr_extend(running_digest2, sha256_2)
                
                # Show full SHA-256 digest
                row.append(sha256_2)
                
                # Also show the running PCR value after this extend
                row.append(running_digest2)
            else:
                row.append("N/A")
                row.append("N/A")
                running_digest2 = "Error"
        else:
            # Placeholders for empty source 2 data
            row.extend(["N/A", "N/A", "N/A", "N/A"])
        
        # Check if digests match for this position
        digest_match = "N/A"
        is_match = False
        if sha256_1 and sha256_2:
            total_comparisons += 1
            # Convert to lowercase for case-insensitive comparison
            if sha256_1.lower() == sha256_2.lower():
                match_count += 1
                digest_match = "✓"
                is_match = True
            else:
                digest_match = "✗"
        
        row.append(digest_match)
        table_data.append(row)
        
        # Save match info for JSON
        digest_matches.append({
            "position": i + 1,
            "source1_digest": sha256_1,
            "source2_digest": sha256_2,
            "match": is_match
        })
    
    # Add final calculated PCR values as the last row
    final_row = [
        "FINAL", "", "Final PCR", "", final_pcr1, 
        "", "Final PCR", "", final_pcr2,
        "✓" if final_pcr_match else "✗"
    ]
    table_data.append(final_row)
    
    # Prepare JSON data for saving
    json_data = {
        "comparison_info": {
            "pcr_index": pcr_index,
            "source1": {
                "id": source_id1,
                "name": source1_name,
                "file": source1.get('source_file', 'N/A'),
                "final_pcr_value": final_pcr1
            },
            "source2": {
                "id": source_id2,
                "name": source2_name,
                "file": source2.get('source_file', 'N/A'),
                "final_pcr_value": final_pcr2
            },
            "match_summary": {
                "total_events_compared": total_comparisons,
                "matching_events": match_count,
                "match_percentage": 0,
                "final_pcr_match": final_pcr_match
            }
        },
        "events": []
    }
    
    # If there were matches, update the match percentage in JSON
    if total_comparisons > 0:
        match_percentage = (match_count / total_comparisons) * 100
        json_data["comparison_info"]["match_summary"]["match_percentage"] = match_percentage
    
    # Display the comparison table
    headers = [
        "Pos", "S1 Event #", "S1 Event Type", "S1 Extend Digest", "S1 PCR Value", 
        "S2 Event #", "S2 Event Type", "S2 Extend Digest", "S2 PCR Value", "Match?"
    ]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Display match summary
    if total_comparisons > 0:
        print(f"\nTotal events compared: {total_comparisons}")
        print(f"Matching digests: {match_count} ({match_percentage:.2f}%)")
    else:
        print("\nNo comparable events found.")
    
    # Show final PCR match status
    if final_pcr1 != "N/A" and final_pcr2 != "N/A":
        if final_pcr_match:
            print("\nFinal PCR values MATCH ✓")
        else:
            print("\nFinal PCR values DO NOT MATCH ✗")
    
    # Build event details for JSON
    for i in range(max_events):
        event_json = {
            "position": i + 1
        }
        
        # Source 1 data
        if i < len(events1):
            event1 = events1[i]
            event_type1 = get_event_type(event1)
            event_num1 = event1.get('event_number', event1.get('event_num', 'N/A'))
            
            # Get SHA-256 digest
            sha256_1 = None
            pcr_value1 = "N/A"
            if 'sha256_digest' in event1:
                sha256_1 = event1['sha256_digest']
                if sha256_1:
                    sha256_1 = sha256_1.lower()
            elif 'digests' in event1 and 'sha256' in event1['digests']:
                sha256_1 = event1['digests']['sha256']
                if sha256_1:
                    sha256_1 = sha256_1.lower()
                
            if sha256_1:
                pcr_value1 = "0" * 64  # Starting PCR value
                # Calculate the PCR value up to this event
                for j in range(i + 1):
                    if j < len(events1):
                        event_digest = get_sha256_digest(events1[j])
                        if event_digest:
                            # Note: get_sha256_digest already returns lowercase
                            pcr_value1 = calculate_pcr_extend(pcr_value1, event_digest)
            
            event_json["source1"] = {
                "event_number": event_num1,
                "event_type": event_type1,
                "extend_digest": sha256_1 if sha256_1 else "N/A",
                "pcr_value": pcr_value1
            }
        
        # Source 2 data
        if i < len(events2):
            event2 = events2[i]
            event_type2 = get_event_type(event2)
            event_num2 = event2.get('event_number', event2.get('event_num', 'N/A'))
            
            # Get SHA-256 digest
            sha256_2 = None
            pcr_value2 = "N/A"
            if 'sha256_digest' in event2:
                sha256_2 = event2['sha256_digest']
                if sha256_2:
                    sha256_2 = sha256_2.lower()
            elif 'digests' in event2 and 'sha256' in event2['digests']:
                sha256_2 = event2['digests']['sha256']
                if sha256_2:
                    sha256_2 = sha256_2.lower()
                
            if sha256_2:
                pcr_value2 = "0" * 64  # Starting PCR value
                # Calculate the PCR value up to this event
                for j in range(i + 1):
                    if j < len(events2):
                        event_digest = get_sha256_digest(events2[j])
                        if event_digest:
                            # Note: get_sha256_digest already returns lowercase
                            pcr_value2 = calculate_pcr_extend(pcr_value2, event_digest)
            
            event_json["source2"] = {
                "event_number": event_num2,
                "event_type": event_type2,
                "extend_digest": sha256_2 if sha256_2 else "N/A",
                "pcr_value": pcr_value2
            }
            
        json_data["events"].append(event_json)
    
    # Save the comparison to a JSON file
    output_dir = os.path.join(os.path.dirname(db.db_file_path), '..', 'output')
    os.makedirs(output_dir, exist_ok=True)
    
    # Use truncated source IDs for the filename
    source1_short = source_id1[:8]
    source2_short = source_id2[:8]
    json_filename = f"pcr{pcr_index}_comparison_{source1_short}_{source2_short}.json"
    json_path = os.path.join(output_dir, json_filename)
    
    with open(json_path, 'w') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\nComparison saved to {json_path}")


def get_sha256_digest(event):
    """
    Extract SHA-256 digest from an event if available.
    Returns the digest in lowercase for consistent comparison.
    """
    if 'sha256_digest' in event:
        digest = event['sha256_digest']
        return digest.lower() if digest else None
    elif 'digests' in event and 'sha256' in event['digests']:
        digest = event['digests']['sha256']
        return digest.lower() if digest else None
    return None


def main():
    """
    Main entry point for the analysis tool.
    """
    parser = argparse.ArgumentParser(description='TPM Event Log Analysis Tool')
    parser.add_argument('--db', type=str, required=True, help='Path to the database file')
    parser.add_argument('--pcr', type=int, default=7, help='PCR index to focus on')
    parser.add_argument('--list-sources', action='store_true', help='List all sources in the database')
    parser.add_argument('--list-pcrs', action='store_true', help='List all PCR indices in the database')
    parser.add_argument('--list-event-types', action='store_true', help='List all event types in the database')
    parser.add_argument('--source1', type=str, help='First source ID for comparison (optional, will auto-select if not provided)')
    parser.add_argument('--source2', type=str, help='Second source ID for comparison (optional, will auto-select if not provided)')
    parser.add_argument('--pcr-values', action='store_true', help='Display calculated PCR values')
    
    args = parser.parse_args()
    
    # Load the database
    db = EventLogDatabase(args.db)
    
    # Get all available sources
    all_sources = db.get_source_ids()
    
    # If only the --list-sources option is specified, just list the sources
    if args.list_sources and not any([args.list_pcrs, args.list_event_types, args.pcr_values]):
        list_sources(db)
        return
    
    # List PCRs
    if args.list_pcrs:
        list_pcrs(db)
        return
    
    # List event types
    if args.list_event_types:
        list_event_types(db, args.pcr)
        return
    
    # Display PCR values
    if args.pcr_values:
        display_pcr_values(db, args.pcr)
        return
    
    # Default behavior: Compare sources
    source_id1 = args.source1
    source_id2 = args.source2
    
    # For default comparison behavior, continue with source selection and comparison
    if not source_id1 and not source_id2 and len(all_sources) >= 2:
        source_id1 = all_sources[0]
        source_id2 = all_sources[1]
        print(f"\nAuto-selected sources for comparison:")
        print(f"Source 1: {source_id1}")
        print(f"Source 2: {source_id2}")
    elif not source_id2 and source_id1 and len(all_sources) >= 2:
        # Find a different source than source_id1
        for src in all_sources:
            if src != source_id1:
                source_id2 = src
                print(f"\nAuto-selected Source 2: {source_id2}")
                break
    elif not source_id1 and source_id2 and len(all_sources) >= 2:
        # Find a different source than source_id2
        for src in all_sources:
            if src != source_id2:
                source_id1 = src
                print(f"\nAuto-selected Source 1: {source_id1}")
                break
    
    if not source_id1 or not source_id2:
        print("Error: Need two sources for comparison. Use --list-sources to see available sources.")
        list_sources(db)
        return
        
    # Use compare_sources for all comparisons
    compare_sources(db, args.pcr, source_id1, source_id2)
    return


if __name__ == "__main__":
    main() 