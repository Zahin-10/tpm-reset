"""
Database management for TPM event logs.

This module provides a database for storing and querying TPM event logs.
"""

import json
import os
import sys
import datetime
import uuid
from typing import List, Dict, Any, Optional, Set, Tuple, Union

# Try absolute imports first for when running directly from TpmEventLog directory
try:
    from core.models import EventLog, PcrEvent, DigestEntry
    from parsers.parser import EventLogParser
except ImportError:
    # Fall back to relative imports for when running as a package
    from ..core.models import EventLog, PcrEvent, DigestEntry
    from ..parsers.parser import EventLogParser


class EventLogDatabase:
    """Manages a database of TPM event logs."""
    
    DEFAULT_DB_FILENAME = os.path.join("db", "tpm_event_logs_database.json")
    
    def __init__(self, db_file_path: Optional[str] = None):
        """
        Initialize the database.
        
        Args:
            db_file_path: Path to the database file. If None, uses the default filename in the db directory.
        """
        self.db_file_path = db_file_path or self.DEFAULT_DB_FILENAME
        
        # Create db directory if it doesn't exist
        db_dir = os.path.dirname(self.db_file_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            
        self.database = self._load_or_create_db()
    
    def _load_or_create_db(self) -> Dict[str, Any]:
        """Load the database from file or create a new one if it doesn't exist."""
        if os.path.exists(self.db_file_path):
            try:
                with open(self.db_file_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"Warning: Could not load database file: {e}")
                return self._create_new_db()
        else:
            return self._create_new_db()
    
    def _create_new_db(self) -> Dict[str, Any]:
        """Create a new empty database structure."""
        return {
            'metadata': {
                'created_at': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'last_updated': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'version': '1.2.0',  # Incrementing version to reflect the chronological storage change
            },
            'sources': {},  # Information about log sources
            'pcrs': {}      # PCR data organized by PCR index and event type
        }
    
    def add_event_log(self, log_parser: EventLogParser, store_raw_events: bool = False) -> str:
        """
        Add an event log to the database.
        
        Args:
            log_parser: The parser containing the event log to add
            store_raw_events: Whether to store raw event data in the database (default: False)
            
        Returns:
            The ID of the added event log
        """
        # Set the store_raw_events flag on the parser
        log_parser._store_raw_events = store_raw_events
        
        # Check if there's already a log from the same source file
        source_file = log_parser.source_file
        existing_source_id = None
        
        for source_id, source in self.database['sources'].items():
            if source.get('source_file') == source_file:
                existing_source_id = source_id
                print(f"Found existing log from the same source file: {source_file}")
                print(f"Replacing source ID: {existing_source_id}")
                break
        
        # If an existing source is found, use its ID, otherwise generate a new one
        if existing_source_id:
            source_id = existing_source_id
            # Remove all references to the old source from PCRs
            for pcr_index, pcr_data in self.database['pcrs'].items():
                if 'events' in pcr_data and source_id in pcr_data['events']:
                    del pcr_data['events'][source_id]
                if 'summary' in pcr_data and source_id in pcr_data['summary']:
                    del pcr_data['summary'][source_id]
        else:
            # Generate a new UUID for the event log
            source_id = str(uuid.uuid4())
        
        # Add the event log to the database
        event_log = log_parser.event_log
        
        # Add source information
        self.database['sources'][source_id] = {
            'source_file': event_log.source_file,
            'name': event_log.name if hasattr(event_log, 'name') else os.path.basename(event_log.source_file),
            'type': event_log.type if hasattr(event_log, 'type') else 'unknown',
            'added_at': datetime.datetime.now().isoformat(),
        }
        
        # Add events by PCR
        for pcr_index in event_log.get_pcr_indices():
            pcr_index_str = str(pcr_index)
            
            # Ensure PCR entry exists
            if pcr_index_str not in self.database['pcrs']:
                self.database['pcrs'][pcr_index_str] = {'events': {}, 'summary': {}}
            
            # Add events for this PCR
            self.database['pcrs'][pcr_index_str]['events'][source_id] = []
            
            pcr_events = event_log.get_events_by_pcr(pcr_index)
            
            # Check if the parser can calculate extended PCR values
            has_calculation = hasattr(log_parser, 'calculate_extended_pcr_value')
                
            # Extract and store events with original order preserved
            for i, event in enumerate(pcr_events):
                event_dict = log_parser.convert_event_to_dict(event)
                # Add event number for easier reference
                event_dict['event_number'] = i + 1
                self.database['pcrs'][pcr_index_str]['events'][source_id].append(event_dict)
            
            # Add PCR value summary if available
            if has_calculation:
                calculated_value = log_parser.calculate_extended_pcr_value(pcr_index)
                if calculated_value:
                    if 'summary' not in self.database['pcrs'][pcr_index_str]:
                        self.database['pcrs'][pcr_index_str]['summary'] = {}
                    
                    self.database['pcrs'][pcr_index_str]['summary'][source_id] = {
                        'calculated_value': calculated_value
                    }
        
        self.save()
        return source_id
    
    def save(self):
        """Save the database to file."""
        with open(self.db_file_path, 'w') as f:
            json.dump(self.database, f, indent=2)
    
    def get_source_ids(self) -> List[str]:
        """Get a list of all source IDs in the database."""
        return list(self.database['sources'].keys())
    
    def get_source_by_id(self, source_id: str) -> Optional[Dict[str, Any]]:
        """
        Get source information by source ID.
        
        Args:
            source_id: The source ID to get information for.
            
        Returns:
            A dictionary with source information, or None if not found.
        """
        if source_id not in self.database.get('sources', {}):
            return None
        
        return self.database['sources'][source_id]
    
    def get_pcr_indices(self) -> List[int]:
        """Get a list of all PCR indices in the database."""
        return [int(idx) for idx in self.database['pcrs'].keys()]
        
    def get_event_types(self, pcr_index: int) -> List[str]:
        """
        Get a list of all event types for a specific PCR index.
        
        Args:
            pcr_index: The PCR index to get event types for.
            
        Returns:
            A list of event types as strings.
        """
        pcr_index_str = str(pcr_index)
        if pcr_index_str not in self.database['pcrs']:
            return []
        
        # Get event types from the events_by_type section
        event_types = list(self.database['pcrs'][pcr_index_str].get('events_by_type', {}).keys())
        return event_types
    
    def get_events_by_type(self, pcr_index: int, event_type: str) -> List[Dict[str, Any]]:
        """
        Get all events of a specific type for a PCR index, ordered by event number.
        
        Args:
            pcr_index: The PCR index to get events for.
            event_type: The event type to filter by.
            
        Returns:
            A list of event dictionaries, ordered by event number.
        """
        pcr_index_str = str(pcr_index)
        event_type_str = str(event_type)
        
        if pcr_index_str not in self.database['pcrs']:
            return []
        
        # Get events from events_by_type section
        events_by_type = self.database['pcrs'][pcr_index_str].get('events_by_type', {})
        if event_type_str not in events_by_type:
            return []
        
        # Return events list, which is already sorted by event number
        return events_by_type[event_type_str].get('events', [])
    
    def get_events_by_source_and_pcr(self, source_id: str, pcr_index: int) -> List[Dict[str, Any]]:
        """
        Get all events for a specific source and PCR in chronological order.
        
        Args:
            source_id: The source ID to get events for.
            pcr_index: The PCR index to get events for.
            
        Returns:
            A list of event dictionaries
        """
        pcr_index_str = str(pcr_index)
        
        if pcr_index_str not in self.database['pcrs']:
            return []
            
        # Check for events in the current structure ('events')
        if ('events' in self.database['pcrs'][pcr_index_str] and 
            source_id in self.database['pcrs'][pcr_index_str]['events']):
            events = self.database['pcrs'][pcr_index_str]['events'][source_id]
            # Add source_id to each event for consistency
            for event in events:
                event['source_id'] = source_id
            return sorted(events, key=lambda x: x.get('event_number', 0))
            
        # If no events found, return empty list
        return []
    
    def get_all_events_by_pcr(self, pcr_index: int) -> List[Dict[str, Any]]:
        """
        Get all events for a PCR index from all sources.
        
        Args:
            pcr_index: The PCR index to get events for.
            
        Returns:
            A list of event dictionaries sorted by event number.
        """
        pcr_index_str = str(pcr_index)
        
        if pcr_index_str not in self.database['pcrs']:
            return []
            
        all_events = []
        
        # Get events from all sources using the current structure
        if 'events' in self.database['pcrs'][pcr_index_str]:
            for source_id, events in self.database['pcrs'][pcr_index_str]['events'].items():
                for event in events:
                    # Add source_id if not already present
                    if 'source_id' not in event:
                        event['source_id'] = source_id
                    all_events.append(event)
        
        # Sort by event number
        return sorted(all_events, key=lambda x: x.get('event_number', 0))
    
    def compare_events_by_source(self, pcr_index: int, source_id1: str, source_id2: str) -> Dict[str, Any]:
        """
        Compare events between two sources for a specific PCR index.
        
        Args:
            pcr_index: The PCR index to compare events for.
            source_id1: The first source ID.
            source_id2: The second source ID.
            
        Returns:
            A dictionary with comparison results.
        """
        pcr_index_str = str(pcr_index)
        if pcr_index_str not in self.database['pcrs']:
            return {'error': f'PCR {pcr_index} not found in database'}
        
        # Get all events for this PCR from both sources
        events1 = [e for e in self.get_all_events_by_pcr(pcr_index) if e.get('source_id') == source_id1]
        events2 = [e for e in self.get_all_events_by_pcr(pcr_index) if e.get('source_id') == source_id2]
        
        # Extract event types with proper handling for different formats
        def extract_event_type(event):
            """Extract event type with fallbacks for different formats"""
            # For YAML logs, event type is often stored directly in a field named "event_type"
            # but might be a numerical value or different format
            if 'event_type' in event:
                event_type = event['event_type']
                if event_type is not None:
                    return str(event_type)
            
            # Check in event_data which is a common location
            event_data = event.get('event_data', {})
            
            # Try different variations of event type fields in event_data
            for field in ['event_type', 'EventType', 'eventType', 'event_name', 'EventName']:
                if field in event_data and event_data[field] is not None:
                    return str(event_data[field])
            
            # For YAML logs, the event type might be stored in a dedicated field 
            # or as part of a composite field
            if event_data:
                # Check if event_data contains a type field
                for field in ['type', 'Type', 'event_type_name', 'EventTypeName']:
                    if field in event_data and event_data[field] is not None:
                        return str(event_data[field])
                
                # Special handling for EFI variable events (common in YAML format)
                if 'Event' in event_data:
                    event_obj = event_data['Event']
                    
                    # If Event is just a string and represents a separator value
                    if isinstance(event_obj, str):
                        # Check if it's a separator event (typically "00000000")
                        if event_obj == "00000000":
                            return "EV_SEPARATOR"
                        return event_obj
                    
                    # If Event is a dictionary with EFI variable information
                    if isinstance(event_obj, dict):
                        # First check standard type fields
                        for field in ['Type', 'String', 'Name', 'Description']:
                            if field in event_obj and event_obj[field] is not None:
                                return str(event_obj[field])
                        
                        # Check if it's an EFI variable event by looking for VariableName
                        if 'VariableName' in event_obj:
                            variable_name = event_obj['VariableName']
                            
                            # Common EFI variable GUIDs and their corresponding event types
                            if variable_name.startswith('8be4df61-93ca-11d2'):
                                return "EV_EFI_VARIABLE_DRIVER_CONFIG"
                            elif variable_name.startswith('d719b2cb-3d3a-4596'):
                                return "EV_EFI_VARIABLE_AUTHORITY"
                            elif variable_name.startswith('605dab50-e046-4300'):
                                return "EV_EFI_VARIABLE_BOOT"
                            
                            # Fallback for any EFI variable
                            return "EV_EFI_VARIABLE"
            
            # Direct key checks for other formats
            for field in ['EventType', 'eventType', 'EventName', 'eventName']:
                if field in event and event[field] is not None:
                    return str(event[field])
                    
            # As a last resort, search for any key that might contain event type information
            for key in event.keys():
                if 'type' in key.lower() and event[key] is not None:
                    return str(event[key])
                if 'event' in key.lower() and event[key] is not None and isinstance(event[key], str):
                    return event[key]
            
            return "Unknown Event Type"  # Return a default value instead of None
        
        # Collect event types from both sources with proper extraction
        event_types1 = set(extract_event_type(e) for e in events1)
        event_types2 = set(extract_event_type(e) for e in events2)
        
        # Remove None values
        event_types1 = {et for et in event_types1 if et is not None}
        event_types2 = {et for et in event_types2 if et is not None}
        
        # Find common and unique event types
        common_event_types = event_types1.intersection(event_types2)
        unique_to_source1 = event_types1 - event_types2
        unique_to_source2 = event_types2 - event_types1
        
        return {
            'common_event_types': list(common_event_types),
            'unique_to_source1': list(unique_to_source1),
            'unique_to_source2': list(unique_to_source2),
            'event_count_source1': len(events1),
            'event_count_source2': len(events2),
            'matching_event_count': sum(1 for e1 in events1 for e2 in events2 
                                     if e1.get('sha256_digest') == e2.get('sha256_digest'))
        } 