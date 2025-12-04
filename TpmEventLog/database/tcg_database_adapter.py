"""
TCG Log Parser to Database Adapter

This module provides adapter functionality to integrate the TCG log parser with the
existing database structure used for YAML TPM logs.
"""

import os
import sys
import hashlib
import datetime
import uuid
from typing import Optional, Dict, Any, List

# Try absolute imports first for when running directly from TpmEventLog directory
try:
    from parsers.tcg_parser import TCGLogParser, TcgLog, TcgPcrEvent
    from core.models import EventLog, PcrEvent, DigestEntry
    from database.database import EventLogDatabase
except ImportError:
    # Fall back to relative imports for when running as a package
    from ..parsers.tcg_parser import TCGLogParser, TcgLog, TcgPcrEvent
    from ..core.models import EventLog, PcrEvent, DigestEntry
    from .database import EventLogDatabase


class TcgLogAdapter:
    """
    Adapter to convert TcgLog objects to EventLog objects compatible with the database.
    """
    
    def __init__(self, tcg_parser: TCGLogParser):
        """
        Initialize the adapter with a TCG parser.
        
        Args:
            tcg_parser: The TCG log parser instance
        """
        self.tcg_parser = tcg_parser
        self.event_log = None
    
    def adapt(self) -> EventLog:
        """
        Convert the TCG log to an EventLog format compatible with the database.
        
        Returns:
            EventLog: The adapted event log
        """
        # Parse the TCG log if not already parsed
        tcg_log = self.tcg_parser.tcg_log
        
        # Create an EventLog object with metadata
        event_log = EventLog(
            version=1,  # Version is not directly available in TCG logs, use a default
            events=[],
            source_file=os.path.basename(self.tcg_parser.log_file_path),
            parsed_at=datetime.datetime.now().isoformat(),
            log_id=str(uuid.uuid4())  # Generate a unique ID for this log
        )
        
        # Sort TCG events by their original order to maintain event numbering
        sorted_tcg_events = sorted(tcg_log.events, key=lambda e: e.original_index if hasattr(e, 'original_index') else 0)
        
        # Adapt events from TCG format to the expected database format
        for i, tcg_event in enumerate(sorted_tcg_events):
            # Skip events without SHA-256 digests if we're focusing on SHA-256
            if not tcg_event.sha256_digest:
                continue
                
            # Create a corresponding PcrEvent
            pcr_event = PcrEvent(
                event_num=tcg_event.original_index if hasattr(tcg_event, 'original_index') else i,
                pcr_index=tcg_event.pcr_index,
                event_type=tcg_event.event_type,
                event_size=0,  # Event size is not directly available, use 0 as placeholder
                event_data=self._extract_event_data(tcg_event)
            )
            
            # Add the SHA-256 digest
            pcr_event.digests.append(DigestEntry(algorithm="sha256", value=tcg_event.sha256_digest))
            
            # Append to the event log
            event_log.events.append(pcr_event)
        
        # Sort events by event number to maintain proper order
        event_log.events.sort(key=lambda e: e.event_num)
        
        self.event_log = event_log
        return event_log
    
    def _extract_event_data(self, tcg_event: TcgPcrEvent) -> Dict[str, Any]:
        """
        Extract event-specific data from a TCG event.
        
        Args:
            tcg_event: The TCG PCR event
            
        Returns:
            Dict: The extracted event data
        """
        # Get the 'Event' field if it exists
        event_data = {}
        if 'Event' in tcg_event.raw_event:
            event_data['Event'] = tcg_event.raw_event['Event']
            
        # Add event type information for better correlation between formats
        if tcg_event.event_type:
            event_data['event_type'] = tcg_event.event_type
            
        # Add any additional metadata that might help with matching
        if 'EventNumber' in tcg_event.raw_event:
            event_data['EventNumber'] = tcg_event.raw_event['EventNumber']
            
        # Include EventName if available, which is often more descriptive
        if 'EventName' in tcg_event.raw_event:
            event_data['EventName'] = tcg_event.raw_event['EventName']
            
        return event_data
    
    def calculate_extended_pcr_value(self, pcr_index: int) -> str:
        """
        Calculate the extended PCR value for a given PCR index.
        This is a wrapper around the TCG parser's calculation method.
        
        Args:
            pcr_index: The PCR index to calculate the value for
            
        Returns:
            str: The calculated PCR value as a hexadecimal string
        """
        return self.tcg_parser.calculate_extended_pcr_value(pcr_index)


class TcgDatabaseManager:
    """
    Manager to handle adding TCG logs to the database.
    """
    
    def __init__(self, db_file_path: Optional[str] = None):
        """
        Initialize the database manager.
        
        Args:
            db_file_path: Optional path to the database file
        """
        self.database = EventLogDatabase(db_file_path)
    
    def add_tcg_log(self, tcg_parser: TCGLogParser, store_raw_events: bool = False) -> str:
        """
        Add a TCG log to the database using the adapter.
        
        Args:
            tcg_parser: The TCG log parser
            store_raw_events: Whether to store raw event data in the database (default: False)
            
        Returns:
            The source ID of the added log
        """
        if not tcg_parser.tcg_log:
            raise ValueError("No TCG log parsed. Call parse() first.")
        
        # Adapt the TCG log to our internal format
        adapter = TcgLogAdapter(tcg_parser)
        event_log = adapter.adapt()
        
        source_file = os.path.basename(tcg_parser.log_file_path)
        source_id = None
        
        # Create a dummy EventLogParser to use with the database
        class DummyEventLogParser:
            def __init__(self, event_log, calculate_fn, store_raw_events):
                self.event_log = event_log
                self.source_file = event_log.source_file
                self._calculate_fn = calculate_fn
                self._store_raw_events = store_raw_events
                
            def calculate_extended_pcr_value(self, pcr_index):
                return self._calculate_fn(pcr_index)
                
            def convert_event_to_dict(self, event):
                # Extract SHA-256 digest from the digests list if available
                sha256_digest = next((d.value for d in event.digests if d.algorithm.lower() == "sha256"), None)
                
                result = {
                    'event_type': event.event_type,
                    'pcr_index': event.pcr_index,
                    'sha256_digest': sha256_digest
                }
                
                # Only include raw event data if requested
                if self._store_raw_events:
                    result['raw_event'] = event.event_data if hasattr(event, 'event_data') else {}
                    
                return result
        
        for existing_id, source in self.database.database['sources'].items():
            if source.get('source_file') == source_file:
                source_id = existing_id
                print(f"Found existing log from the same source file: {source_file}")
                print(f"Replacing source ID: {source_id}")
                
                # Create the dummy parser with our adapted event log
                dummy_parser = DummyEventLogParser(
                    event_log,
                    tcg_parser.calculate_extended_pcr_value,
                    store_raw_events
                )
                
                # Add the log to the database, which will replace existing entries from the same source
                return self.database.add_event_log(dummy_parser)
        
        # If no existing log was found, add it normally
        # Create the dummy parser with our adapted event log
        dummy_parser = DummyEventLogParser(
            event_log,
            tcg_parser.calculate_extended_pcr_value,
            store_raw_events
        )
        
        # Add the log to the database
        return self.database.add_event_log(dummy_parser)


def example_add_tcg_log_to_database():
    """
    Example showing how to add a TCG log to the database.
    
    This example demonstrates how to add a TCG log with and without raw event data.
    """
    # Define paths
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    log_file = os.path.join(data_dir, "TCGlog_SRTMCurrent.json")
    
    # Parse the TCG log
    tcg_parser = TCGLogParser(log_file)
    tcg_log = tcg_parser.parse()
    
    # Create the database manager
    db_manager = TcgDatabaseManager()
    
    # Example 1: Add log without raw event data (minimal database size)
    source_id1 = db_manager.add_tcg_log(tcg_parser, store_raw_events=False)
    print(f"Added TCG log to database without raw events. Source ID: {source_id1}")
    
    # Example 2: Add log with raw event data (larger database size, but more details)
    source_id2 = db_manager.add_tcg_log(tcg_parser, store_raw_events=True)
    print(f"Added TCG log to database with raw events. Source ID: {source_id2}")
    
    print(f"Database saved to: {db_manager.database.db_file_path}")


if __name__ == "__main__":
    example_add_tcg_log_to_database() 