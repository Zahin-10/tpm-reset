"""
Parser for TPM event logs.
"""

import os
import sys
import yaml
import hashlib
import datetime
import uuid
from typing import Dict, Any, List

# Try absolute imports first for when running directly from TpmEventLog directory
try:
    from core.models import EventLog, PcrEvent, DigestEntry
except ImportError:
    # Fall back to relative imports for when running as a package
    from ..core.models import EventLog, PcrEvent, DigestEntry


class EventLogParser:
    """Parser for TPM event logs."""
    
    def __init__(self, log_file_path: str):
        """Initialize the parser with the path to the log file."""
        self.log_file_path = log_file_path
        self.event_log = None
        self._store_raw_events = False  # Default to not storing raw events
    
    @property
    def source_file(self):
        """Return the source file path for the event log."""
        return os.path.basename(self.log_file_path)
    
    def parse(self) -> EventLog:
        """Parse the event log file and return an EventLog object."""
        with open(self.log_file_path, 'r') as f:
            raw_log = yaml.safe_load(f)
        
        # Create EventLog with metadata
        event_log = EventLog(
            version=raw_log['version'], 
            events=[],
            source_file=self.source_file,
            parsed_at=datetime.datetime.now().isoformat(),
            log_id=str(uuid.uuid4())  # Generate a unique ID for this log
        )
        
        for event_data in raw_log['events']:
            pcr_event = PcrEvent(
                event_num=event_data.get('EventNum'),
                pcr_index=event_data.get('PCRIndex'),
                event_type=event_data.get('EventType'),
                event_size=event_data.get('EventSize'),
                event_data=self._extract_event_data(event_data)
            )
            
            # Extract digests - updated to match the actual structure
            if 'Digests' in event_data:
                for digest_entry in event_data['Digests']:
                    if 'AlgorithmId' in digest_entry and 'Digest' in digest_entry:
                        algorithm = digest_entry['AlgorithmId']
                        digest_value = digest_entry['Digest']
                        pcr_event.digests.append(DigestEntry(algorithm=algorithm, value=digest_value))
            elif 'Digest' in event_data:
                # Handle special case for older format or single digest
                pcr_event.digests.append(DigestEntry(algorithm="sha1", value=event_data['Digest']))
            
            event_log.events.append(pcr_event)
        
        self.event_log = event_log
        return event_log
    
    def _extract_event_data(self, event_data: Dict[str, Any]) -> Any:
        """Extract the event-specific data from an event entry."""
        # Remove standard fields to get only event-specific data
        standard_fields = {'EventNum', 'PCRIndex', 'EventType', 'Digest', 'Digests', 'DigestCount', 'EventSize'}
        event_specific_data = {k: v for k, v in event_data.items() if k not in standard_fields}
        
        # Include 'Event' in event_data if present
        if 'Event' in event_data:
            event_specific_data['Event'] = event_data['Event']
            
        return event_specific_data
    
    def calculate_extended_pcr_value(self, pcr_index: int) -> str:
        """
        Calculate the extended PCR value for a given PCR index.
        This simulates the actual PCR extension process using SHA-256.
        
        Args:
            pcr_index: The PCR index to calculate the value for.
            
        Returns:
            The calculated PCR value as a hexadecimal string.
        """
        if self.event_log is None:
            raise ValueError("No event log parsed yet. Call parse() first.")
        
        # Start with initial PCR value (all zeros)
        pcr_value = bytes.fromhex("0" * 64)
        
        # Get all sha256 events for this PCR
        pcr_events = self.event_log.get_events_by_pcr(pcr_index)
        
        # Extend PCR value with each event
        for event in pcr_events:
            sha256_digest = next((d.value for d in event.digests if d.algorithm.lower() == "sha256"), None)
            if sha256_digest:
                # Perform the PCR extend operation: PCR_new = SHA256(PCR_old || measurement)
                digest_bytes = bytes.fromhex(sha256_digest)
                pcr_value = hashlib.sha256(pcr_value + digest_bytes).digest()
        
        return pcr_value.hex() 

    def convert_event_to_dict(self, event):
        """
        Convert a PCR event object to a dictionary representation.
        
        Args:
            event: The PcrEvent to convert
            
        Returns:
            Dictionary representation of the event
        """
        # Extract the SHA-256 digest if available
        sha256_digest = next((d.value for d in event.digests if d.algorithm.lower() == "sha256"), None)
        
        result = {
            'event_type': event.event_type,
            'pcr_index': event.pcr_index,
            'event_num': event.event_num,
            'event_size': event.event_size,
            'sha256_digest': sha256_digest,
            'digests': [{'algorithm': d.algorithm, 'value': d.value} for d in event.digests]
        }
        
        # Only include raw event data if requested
        if self._store_raw_events:
            result['event_data'] = event.event_data
            
        return result 