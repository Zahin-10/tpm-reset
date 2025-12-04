#!/usr/bin/env python3

"""
PCR Extend Command Module

This module provides functionality to run PCR extend commands using ESAPI based on summary data.
It allows repeating the PCR extensions found in a summary file up to a specified position.
By default, it will extend up to and including the first EV_SEPARATOR event.
When a max-event is specified, it will extend up to that event regardless of EV_SEPARATOR events.
After completing the summary file extensions, it performs one additional extension using
the pcr7_measured_boot.py digest calculation.
"""

import os
import json
import argparse
import sys
from typing import Dict, List, Any, Optional

# Get the absolute path to the parent directory
parent_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

from tpm.esapi_interface import ESAPIInterface
from .pcr7_measured_boot import Certificate, UefiGuid, UefiVariable

# Event type constants
EV_SEPARATOR = "EV_SEPARATOR"

def load_summary_file(summary_file: str) -> Dict[str, Any]:
    """
    Load and parse a summary JSON file.
    
    Args:
        summary_file: Path to the summary JSON file
        
    Returns:
        The parsed summary data as a dictionary
    """
    try:
        with open(summary_file, 'r') as f:
            summary_data = json.load(f)
            return summary_data
    except Exception as e:
        print(f"Error loading summary file: {str(e)}")
        sys.exit(1)

def extract_pcr_events(summary_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract PCR events from the summary data.
    
    Args:
        summary_data: The summary data dictionary
        
    Returns:
        A list of PCR events with their digests
    """
    events = []
    
    # Extract PCR index - check both direct top-level and in summary_info
    pcr_index = summary_data.get('pcr_index')
    if pcr_index is None and 'summary_info' in summary_data:
        pcr_index = summary_data.get('summary_info', {}).get('pcr_index')
    
    if pcr_index is None:
        print("Error: Could not find PCR index in summary file")
        sys.exit(1)
        
    # Extract events
    if 'events' not in summary_data:
        print("Error: No events found in summary file")
        sys.exit(1)
        
    for event in summary_data['events']:
        # Extract the SHA-256 digest
        digest = None
        
        # Check if there's a direct sha256_digest field
        if 'sha256_digest' in event:
            digest = event['sha256_digest']
        # Check if there's an extend_digest field
        elif 'extend_digest' in event:
            digest = event['extend_digest']
        # Otherwise look in digests list
        elif 'digests' in event:
            for d in event['digests']:
                if d.get('algorithm', '').lower() == 'sha256':
                    digest = d.get('value')
                    break
        
        if digest:
            events.append({
                'position': event.get('position', 0),
                'event_number': event.get('event_number', 0),
                'event_type': event.get('event_type', 'Unknown'),
                'digest': digest
            })
        else:
            print(f"Warning: No SHA-256 digest found for event {event.get('event_number', 'unknown')}")
    
    return events

def calculate_pcr7_measured_boot_digest(cert_path: str = None, guid_str: Optional[str] = None) -> Optional[str]:
    """
    Calculate the digest for PCR7 measured boot using the code from pcr7_measured_boot.py.
    
    Args:
        cert_path: Path to certificate in DER format
        guid_str: Optional custom GUID string for the UEFI variable
        
    Returns:
        The calculated digest as a hex string, or None if calculation failed
    """
    if not cert_path:
        print("No certificate path provided for PCR7 measured boot digest calculation")
        return None
    
    try:
        # Create certificate and measure it
        certificate = Certificate(cert_path)
        # owner_guid should be an instance of UefiGuid, initialized with guid_str.
        # This instance is used for the UEFI_VARIABLE_DATA.VariableName field.
        owner_guid = UefiGuid(guid_str)
        
        # Extract signature data, passing the raw guid_str for the EFI_SIGNATURE_DATA owner.
        # create_signature_data will handle creating UefiGuid from guid_str internally.
        sig_data = certificate.create_signature_data(owner_guid)
        
        # Create UEFI variable (using owner_guid UefiGuid instance for UEFI_VARIABLE_DATA.VariableName)
        variable = UefiVariable("db", sig_data)
        digest, _ = variable.measure()
        digest_hex = digest.hex().lower()
        
        return digest_hex
    except Exception as e:
        print(f"Error calculating PCR7 measured boot digest: {str(e)}")
        return None

def run_pcr_extensions(pcr_index: int, events: List[Dict[str, Any]], max_event: int, 
                      tcti_connection: Optional[str] = None, reset_pcr: bool = False,
                      cert_path: Optional[str] = None,
                      pcr7_guid_str: Optional[str] = None) -> bool:
    """
    Run PCR extensions using ESAPI up to the specified event.
    
    Args:
        pcr_index: The PCR index to extend
        events: List of events with their digests
        max_event: Maximum event number to process (inclusive)
        tcti_connection: Optional TCTI connection string for the TPM
        reset_pcr: Whether to attempt to reset the PCR first
        cert_path: Path to certificate in DER format for PCR7 measured boot digest
        pcr7_guid_str: Optional custom GUID string for the PCR7 measured boot digest calculation
        
    Returns:
        True if successful, False otherwise
    """
    try:
        # Initialize ESAPI interface with context manager
        with ESAPIInterface(tcti_connection) as esapi:
            # Attempt to reset PCR if requested
            # if reset_pcr:
            #     print(f"Attempting to reset PCR {pcr_index}...")
            #     if not esapi.reset_pcr(pcr_index):
            #         print(f"Warning: Could not reset PCR {pcr_index}. Continuing with current value.")
            
            # Read initial PCR value
            initial_value = esapi.read_pcr(pcr_index)
            if initial_value:
                print(f"Initial PCR {pcr_index} value: {initial_value}")
            
            success = True
            events_processed = 0
            
            # Determine if we should stop at separator
            # If max_event is explicitly set (not infinity), we ignore separators
            stop_at_separator = max_event == float('inf')
            
            # Process events in their original order
            for event in events:
                position = event.get('position', 0)
                if position > max_event:
                    break
                    
                event_num = event.get('event_number', 0)
                event_type = event.get('event_type', 'Unknown')
                print(f"\nProcessing event position {position} (event_number {event_num}): {event_type}")
                digest = event['digest']
                
                if not esapi.extend_pcr(pcr_index, digest):
                    print(f"Failed to extend PCR {pcr_index} with event position {position}")
                    success = False
                    break
                    
                events_processed += 1
                
                # Stop after processing an EV_SEPARATOR event if we should stop at separators
                if stop_at_separator and event_type == EV_SEPARATOR:
                    print(f"Found EV_SEPARATOR event at position {position}. Stopping PCR extensions.")
                    break
            
            # After completing the regular extensions, do the extra PCR7 measured boot extension
            if success and cert_path:
                print("\nPerforming additional PCR extension using PCR7 measured boot digest...")
                pcr7_digest = calculate_pcr7_measured_boot_digest(cert_path, pcr7_guid_str)
                
                if pcr7_digest:
                    print(f"Calculated PCR7 measured boot digest: {pcr7_digest}")
                    
                    if not esapi.extend_pcr(pcr_index, pcr7_digest):
                        print(f"Failed to extend PCR {pcr_index} with PCR7 measured boot digest")
                        success = False
                    else:
                        events_processed += 1
                else:
                    print("Failed to calculate PCR7 measured boot digest")
                    success = False
            
            # Read final PCR value
            final_value = esapi.read_pcr(pcr_index)
            if final_value:
                print(f"\nFinal PCR {pcr_index} value after {events_processed} extensions: {final_value}")
            
            return success
    
    except Exception as e:
        print(f"Error during PCR extension process: {str(e)}")
        return False

def main():
    """Main entry point for the PCR extend command."""
    parser = argparse.ArgumentParser(
        description='Run PCR extend commands using ESAPI based on summary data')
    
    parser.add_argument('summary_file', help='Path to the summary JSON file')
    parser.add_argument('--max-event', type=int, 
                       help='Maximum event number to process (inclusive). When specified, EV_SEPARATOR events are ignored.')
    parser.add_argument('--tcti', help='TCTI connection string (e.g., "swtpm:host=localhost,port=2321")')
    parser.add_argument('--reset', action='store_true', 
                       help='Attempt to reset the PCR before extending (only works for PCRs 16-23)')
    parser.add_argument('--cert', help='Path to certificate in DER format for PCR7 measured boot digest')
    parser.add_argument('--pcr7-guid', help='Custom UEFI GUID for the PCR7 measured boot digest calculation (e.g., xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)')
    
    args = parser.parse_args()
    
    # Load summary file
    summary_data = load_summary_file(args.summary_file)
    
    # Extract PCR index - check both direct top-level and in summary_info
    pcr_index = summary_data.get('pcr_index')
    if pcr_index is None and 'summary_info' in summary_data:
        pcr_index = summary_data.get('summary_info', {}).get('pcr_index')
    
    if pcr_index is None:
        print("Error: Could not find PCR index in summary file")
        sys.exit(1)
    
    # Extract events with their digests
    events = extract_pcr_events(summary_data)
    if not events:
        print("No events with valid digests found in summary file")
        sys.exit(1)
    
    # Determine max event to process
    max_event = args.max_event if args.max_event is not None else float('inf')
    
    # Run PCR extensions
    success = run_pcr_extensions(
        pcr_index, 
        events, 
        max_event,
        tcti_connection=args.tcti,
        reset_pcr=args.reset,
        cert_path=args.cert,
        pcr7_guid_str=args.pcr7_guid
    )
    
    if success:
        print("\nPCR extension completed successfully!")
    else:
        print("\nPCR extension failed.")
        sys.exit(1)

if __name__ == "__main__":
    main() 