"""
Data models for TPM event log parsing.
"""

from dataclasses import dataclass, field
from typing import List, Any, Optional
import os


@dataclass
class DigestEntry:
    """Class representing a single digest entry in a PCR event."""
    algorithm: str
    value: str


@dataclass
class PcrEvent:
    """Class representing a single PCR event."""
    event_num: int
    pcr_index: int
    event_type: str
    event_size: int
    event_data: Any
    digests: List[DigestEntry] = field(default_factory=list)


@dataclass
class EventLog:
    """Class representing the entire TPM event log."""
    version: int
    events: List[PcrEvent] = field(default_factory=list)
    source_file: str = ""
    parsed_at: str = ""
    log_id: str = ""  # Unique ID for this log
    
    @property
    def name(self) -> str:
        """Return a friendly name for the event log."""
        return os.path.basename(self.source_file)
    
    @property
    def type(self) -> str:
        """Return the type of the event log."""
        return "yaml"
    
    @property
    def sha256_events(self) -> List[PcrEvent]:
        """Return only events that have SHA-256 digests."""
        return [event for event in self.events if any(d.algorithm.lower() == "sha256" for d in event.digests)]
    
    def get_events_by_pcr(self, pcr_index: int) -> List[PcrEvent]:
        """Return all events for a specific PCR index."""
        return [event for event in self.sha256_events if event.pcr_index == pcr_index]
        
    def get_pcr_indices(self) -> List[int]:
        """Return a list of all PCR indices in the log."""
        return sorted(list({event.pcr_index for event in self.sha256_events})) 