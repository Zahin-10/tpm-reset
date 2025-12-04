#!/usr/bin/env python3
"""
TCG Log Parser for TPM Events

This module provides a parser for TCG (Trusted Computing Group) log files in JSON format.
It extracts PCR events and their corresponding SHA-256 digests from the log file.

The parser is specifically designed to work with TCG log files in UTF-16 JSON format,
where each event has a Digest field containing multiple hash values,
with the second value being the SHA-256 digest.

Example usage:
    parser = TCGLogParser("path/to/tcg_log.json")
    tcg_log = parser.parse()
    
    # Get all events with SHA-256 digests
    sha256_events = tcg_log.get_events_with_sha256()
    
    # Calculate a PCR value
    pcr_value = parser.calculate_extended_pcr_value(0)  # PCR 0
"""

import json
import os
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Union

# Set up logging
logger = logging.getLogger(__name__)


@dataclass
class TcgPcrEvent:
    """Class representing a TPM PCR event from a TCG log."""
    pcr_index: int
    event_type: str
    sha256_digest: Optional[str]
    raw_event: Dict[str, Any]  # The original event data
    original_index: int = -1  # Track the original order in the log


@dataclass
class TcgLog:
    """Class representing the parsed TCG log file."""
    events: List[TcgPcrEvent] = field(default_factory=list)
    source_file: str = ""
    
    def get_events_by_pcr(self, pcr_index: int) -> List[TcgPcrEvent]:
        """
        Return all events for a specific PCR index.
        
        Args:
            pcr_index: The PCR index to filter by
            
        Returns:
            A list of PCR events for the specified index
        """
        return [event for event in self.events if event.pcr_index == pcr_index]
    
    def get_events_with_sha256(self) -> List[TcgPcrEvent]:
        """
        Return only events that have SHA-256 digests.
        
        Returns:
            A list of PCR events that have SHA-256 digests
        """
        return [event for event in self.events if event.sha256_digest]
    
    def get_pcr_indices(self) -> Set[int]:
        """
        Return a set of all PCR indices in the log.
        
        Returns:
            A set of PCR indices
        """
        return {event.pcr_index for event in self.events}
    
    def get_event_types(self) -> Set[str]:
        """
        Return a set of all event types in the log.
        
        Returns:
            A set of event type strings
        """
        return {event.event_type for event in self.events}


class TCGLogParser:
    """Parser for TCG log files in UTF-16 JSON format."""
    
    def __init__(self, log_file_path: str, verbose: bool = False):
        """
        Initialize the parser with a path to a TCG log file.
        
        Args:
            log_file_path: Path to the TCG log file
            verbose: If True, enable verbose logging
        """
        self.log_file_path = log_file_path
        self.tcg_log = TcgLog(source_file=os.path.basename(log_file_path))
        
        # Set up logging
        log_level = logging.INFO if verbose else logging.WARNING
        logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')
        
    def parse(self) -> TcgLog:
        """
        Parse the TCG log file and extract PCR events with SHA-256 digests.
        
        Returns:
            TcgLog: Object containing the parsed events
            
        Raises:
            FileNotFoundError: If the log file doesn't exist
            json.JSONDecodeError: If the log file is not valid JSON
            ValueError: If the log file has an unexpected format
        """
        if not os.path.exists(self.log_file_path):
            raise FileNotFoundError(f"Log file not found: {self.log_file_path}")
        
        # Detect file encoding and parse accordingly
        data = self._load_json_file()
        
        # Handle header event separately
        self._parse_header(data)
        
        # Process the events for each PCR
        self._parse_events(data)
        
        logger.info(f"Parsed {len(self.tcg_log.events)} events, "
                    f"{len(self.tcg_log.get_events_with_sha256())} with SHA-256 digests")
        
        return self.tcg_log
    
    def _load_json_file(self) -> Dict[str, Any]:
        """
        Load the JSON file with appropriate encoding detection.
        
        Returns:
            The parsed JSON data
            
        Raises:
            json.JSONDecodeError: If the file is not valid JSON
        """
        encodings = ['utf-16', 'utf-8', 'latin-1']
        
        for encoding in encodings:
            try:
                with open(self.log_file_path, 'r', encoding=encoding) as f:
                    return json.load(f)
            except UnicodeError:
                continue
            except json.JSONDecodeError:
                if encoding == encodings[-1]:  # Last encoding attempt
                    raise
                continue
        
        # If we get here, none of the encodings worked
        raise ValueError(f"Could not decode {self.log_file_path} with any of {encodings}")
    
    def _parse_header(self, data: Dict[str, Any]) -> None:
        """
        Parse the header section of the TCG log.
        
        Args:
            data: The loaded JSON data
        """
        header = data.get('Header', {})
        if not header:
            logger.warning("No 'Header' section found in the log file")
            return
            
        pcr_index = header.get('PCR', 0)
        event_type = header.get('EventType', '')
        sha256_digest = None  # Header typically doesn't have a SHA-256 digest
        
        header_event = TcgPcrEvent(
            pcr_index=pcr_index,
            event_type=event_type,
            sha256_digest=sha256_digest,
            raw_event=header
        )
        self.tcg_log.events.append(header_event)
    
    def _parse_events(self, data: Dict[str, Any]) -> None:
        """
        Parse the PCR events from the TCG log.
        
        Args:
            data: The loaded JSON data
        """
        events_section = data.get('Events', {})
        if not events_section:
            logger.warning("No 'Events' section found in the log file or it's empty")
            return
        
        # Counter to track the original event order
        event_counter = 0
        
        for pcr_key, events in events_section.items():
            # Extract PCR index from key (e.g., 'PCR0' -> 0)
            try:
                pcr_index = int(pcr_key.replace('PCR', ''))
            except ValueError:
                logger.warning(f"Skipping invalid PCR key: {pcr_key}")
                continue
            
            # Skip if events is None or not a list
            if events is None or not isinstance(events, list):
                logger.debug(f"Events for {pcr_key} is not a list or is None")
                continue
                
            for event in events:
                if not isinstance(event, dict):
                    logger.debug(f"Skipping non-dictionary event in {pcr_key}")
                    continue
                
                # Extract SHA-256 digest
                sha256_digest = self._extract_sha256_digest(event)
                
                pcr_event = TcgPcrEvent(
                    pcr_index=pcr_index,
                    event_type=event.get('EventType', ''),
                    sha256_digest=sha256_digest,
                    raw_event=event,
                    original_index=event_counter  # Add the original index
                )
                self.tcg_log.events.append(pcr_event)
                event_counter += 1
    
    def _extract_sha256_digest(self, event: Dict[str, Any]) -> Optional[str]:
        """
        Extract the SHA-256 digest from an event.
        
        Args:
            event: The event data dictionary
            
        Returns:
            str: The SHA-256 digest value, or None if not found
        """
        digest = event.get('Digest')
        
        # Handle different digest formats
        if digest is None:
            return None
        
        # Case 1: Digest is a dictionary with 'value' list (common format)
        if isinstance(digest, dict) and 'value' in digest:
            value_list = digest['value']
            if isinstance(value_list, list) and len(value_list) >= 2:
                return value_list[1]  # SHA-256 is the second digest
        
        # Case 2: Digest is a string (sometimes for EV_NO_ACTION)
        elif isinstance(digest, str):
            # It might be a single digest, but not SHA-256
            # SHA-256 digests should be 64 characters long
            if len(digest) == 64:
                return digest
        
        return None

    def calculate_extended_pcr_value(self, pcr_index: int) -> str:
        """
        Calculate the extended PCR value for a given PCR index using SHA-256.
        
        This function simulates the TPM's PCR extension process by starting with
        a zero value and then extending it with each event's SHA-256 digest.
        
        Args:
            pcr_index: The PCR index to calculate
            
        Returns:
            str: The calculated PCR value as a hexadecimal string
        """
        import hashlib
        
        # Start with initial PCR value (all zeros)
        pcr_value = bytes.fromhex("0" * 64)
        
        # Get all events for this PCR that have SHA-256 digests
        pcr_events = [event for event in self.tcg_log.get_events_by_pcr(pcr_index) 
                     if event.sha256_digest]
        
        # Extend PCR value with each event
        for event in pcr_events:
            try:
                # Perform the PCR extend operation: PCR_new = SHA256(PCR_old || measurement)
                digest_bytes = bytes.fromhex(event.sha256_digest)
                pcr_value = hashlib.sha256(pcr_value + digest_bytes).digest()
            except ValueError as e:
                logger.warning(f"Error extending PCR {pcr_index} with event {event.event_type}: {e}")
        
        return pcr_value.hex()
    
    def print_events_summary(self) -> None:
        """Print a summary of the parsed events."""
        pcr_counts = {}
        sha256_pcr_counts = {}
        
        for event in self.tcg_log.events:
            pcr_counts[event.pcr_index] = pcr_counts.get(event.pcr_index, 0) + 1
            
            if event.sha256_digest:
                sha256_pcr_counts[event.pcr_index] = sha256_pcr_counts.get(event.pcr_index, 0) + 1
        
        print(f"TCG Log File: {self.log_file_path}")
        print(f"Total events: {len(self.tcg_log.events)}")
        print(f"Events with SHA-256 digests: {len(self.tcg_log.get_events_with_sha256())}")
        
        print("\nEvents per PCR:")
        for pcr, count in sorted(pcr_counts.items()):
            sha256_count = sha256_pcr_counts.get(pcr, 0)
            print(f"  PCR {pcr}: {count} events ({sha256_count} with SHA-256 digests)")
        
        print("\nEvent types found:")
        for event_type in sorted(self.tcg_log.get_event_types()):
            print(f"  {event_type}")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python tcg_parser.py <tcg_log_file> [pcr_index]")
        sys.exit(1)
    
    log_file = sys.argv[1]
    # If path doesn't exist but might be in the data directory
    if not os.path.exists(log_file) and not os.path.dirname(log_file):
        data_dir = os.path.join(os.path.dirname(__file__), "data")
        log_file = os.path.join(data_dir, log_file)
    
    parser = TCGLogParser(log_file)
    log = parser.parse()
    
    parser.print_events_summary()
    
    # Optionally calculate and print a specific PCR value
    if len(sys.argv) > 2:
        try:
            pcr_to_calculate = int(sys.argv[2])
            print(f"\nCalculated PCR {pcr_to_calculate} value (SHA-256): {parser.calculate_extended_pcr_value(pcr_to_calculate)}")
        except ValueError:
            print(f"Invalid PCR index: {sys.argv[2]}") 