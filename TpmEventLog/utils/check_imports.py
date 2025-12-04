#!/usr/bin/env python3
"""
Simple script to check that all imports work correctly.
"""

print("Checking imports...")
try:
    from TpmEventLog.models import DigestEntry, PcrEvent, EventLog
    print("✓ models.py imported successfully")
    
    from TpmEventLog.parser import EventLogParser
    print("✓ parser.py imported successfully")
    
    from TpmEventLog.database import EventLogDatabase
    print("✓ database.py imported successfully")
    
    from TpmEventLog.__main__ import main
    print("✓ __main__.py imported successfully")
    
    print("\nAll imports successful!")
except ImportError as e:
    print(f"✗ Import error: {e}")
    print("\nPossible issues:")
    print("1. You might be running this script from outside the package directory")
    print("2. The package structure might be incorrect")
    print("3. Dependencies might be missing")
    print("\nRecommended solution: Run 'pip install pyyaml' and try again") 