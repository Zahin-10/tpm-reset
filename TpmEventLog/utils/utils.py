"""
Utility functions for TPM event log analysis.
"""

import hashlib
from typing import Dict, List, Any, Optional


def calculate_pcr_extend(initial_value: str, measurement: str) -> str:
    """
    Calculate the PCR extend operation: PCR_new = SHA256(PCR_old || measurement).
    
    Args:
        initial_value: Initial PCR value as a hex string
        measurement: Measurement to extend with as a hex string
        
    Returns:
        The new PCR value as a hex string
    """
    initial_bytes = bytes.fromhex(initial_value)
    measurement_bytes = bytes.fromhex(measurement)
    return hashlib.sha256(initial_bytes + measurement_bytes).digest().hex()


def compare_pcr_values(value1: str, value2: str) -> bool:
    """
    Compare two PCR values for equality.
    
    Args:
        value1: First PCR value as a hex string
        value2: Second PCR value as a hex string
        
    Returns:
        True if the values match, False otherwise
    """
    return value1.lower() == value2.lower()


def find_pcr_mismatch(db_data: Dict[str, Any], pcr_index: int, source_id1: str, source_id2: str) -> List[Dict[str, Any]]:
    """
    Find events that cause a PCR mismatch between two sources.
    
    Args:
        db_data: Database data
        pcr_index: PCR index to check
        source_id1: First source ID
        source_id2: Second source ID
        
    Returns:
        List of events that differ between the sources
    """
    pcr_str = str(pcr_index)
    if pcr_str not in db_data['pcrs']:
        return []
    
    pcr_data = db_data['pcrs'][pcr_str]
    mismatches = []
    
    for event_num, event_data in pcr_data['events'].items():
        sources = event_data.get('sources', {})
        
        # Check if both sources have this event
        if source_id1 in sources and source_id2 in sources:
            source1_data = sources[source_id1]
            source2_data = sources[source_id2]
            
            # Compare digests
            if source1_data.get('sha256_digest') != source2_data.get('sha256_digest'):
                mismatches.append({
                    'pcr_index': pcr_index,
                    'event_num': int(event_num),
                    'source1': {
                        'source_id': source_id1,
                        'event_type': source1_data.get('event_type'),
                        'digest': source1_data.get('sha256_digest')
                    },
                    'source2': {
                        'source_id': source_id2,
                        'event_type': source2_data.get('event_type'),
                        'digest': source2_data.get('sha256_digest')
                    }
                })
        # Check if only one source has this event
        elif source_id1 in sources or source_id2 in sources:
            missing_source = source_id2 if source_id1 in sources else source_id1
            present_source = source_id1 if source_id1 in sources else source_id2
            present_data = sources[present_source]
            
            mismatches.append({
                'pcr_index': pcr_index,
                'event_num': int(event_num),
                f'{present_source}': {
                    'source_id': present_source,
                    'event_type': present_data.get('event_type'),
                    'digest': present_data.get('sha256_digest')
                },
                f'{missing_source}': {
                    'source_id': missing_source,
                    'status': 'missing'
                }
            })
    
    return mismatches 