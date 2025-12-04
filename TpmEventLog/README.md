# TPM Event Log Parser

This package provides tools for parsing TPM event logs, extracting PCR events with their SHA-256 digests, and maintaining a database of events from multiple logs.

## Package Structure

The package has been organized into the following modules:

```
TpmEventLog/
├── __init__.py        # Main package initialization
├── main.py            # Unified entry point
├── core/              # Core data models and functionality
│   ├── __init__.py
│   └── models.py      # Data model classes
├── parsers/           # Log parser implementations
│   ├── __init__.py
│   ├── parser.py      # YAML parser
│   ├── tcg_parser.py  # TCG JSON parser
│   └── bitlocker_parser.py  # BitLocker metadata parser
├── database/          # Database management
│   ├── __init__.py
│   ├── database.py    # Main database functionality 
│   └── tcg_database_adapter.py  # Adapter for TCG logs
├── cli/               # Command-line interfaces
│   ├── __init__.py
│   ├── tpm_parser.py  # CLI for YAML parser
│   ├── run_tcg_parser.py  # CLI for TCG parser
│   ├── analyse.py     # CLI for analysis and comparison
│   ├── summary.py     # CLI for generating summaries
│   ├── pcr_extend.py  # CLI for extending PCRs
│   ├── pcr7_measured_boot.py  # CLI for PCR7 measured boot digest calculation
│   └── bitlocker_parser_cli.py  # CLI for BitLocker parser
├── utils/             # Utility functions
│   ├── __init__.py
│   ├── utils.py       # General utilities
│   └── check_imports.py  # Import verification
├── data/              # Directory for log files
│   └── metadata/      # Directory for BitLocker metadata files
├── db/                # Directory for database files 
└── tests/             # Test suite
    └── __init__.py
```

## Core Components

- **Models**: Data classes representing TPM event logs, PCR events, and digest entries
- **Parsers**: Classes to parse different formats of TPM event logs (YAML and TCG JSON)
- **Database**: Classes to manage a database of TPM event logs and support querying
- **PCR7 Measured Boot**: Tools to calculate expected PCR7 digests for UEFI Secure Boot variables
- **BitLocker Parser**: Tools to extract TPM structures from BitLocker metadata

## Usage

### Command Line

The package provides a unified command-line interface that should be run from within the TpmEventLog directory:

```bash
# Change to the TpmEventLog directory
cd TpmEventLog

# Parse a YAML log file
python main.py yaml path/to/log.yaml

# Parse a TCG JSON log file
python main.py tcg path/to/log.json

# Specify a custom database file
python main.py yaml path/to/log.yaml --db custom_database.json

# Analyze PCR events
python main.py analyse --db db/logs.json --pcr 7

# Generate a summary for PCR 7
python main.py summary --db db/logs.json --pcr 7

# Extend PCRs using a summary file (stops at EV_SEPARATOR by default)
python main.py extend output/pcr7_source_12345678_summary.json

# Extend PCRs up to a specific event number (ignores EV_SEPARATOR events)
python main.py extend output/pcr7_source_12345678_summary.json --max-event 10

# Calculate PCR7 digest for a certificate
python main.py pcr7-digest --cert path/to/cert.der --expected "expected_digest_value"

# Parse BitLocker metadata and extract TPM structures
python main.py parse-bitlocker-vmk metadata-secboot

# Parse BitLocker metadata with custom output directory
python main.py parse-bitlocker-vmk metadata-secboot --output-dir output/metadata-keys
```

You can also run the individual parsers directly:

```bash
# YAML parser
python cli/tpm_parser.py path/to/log.yaml

# TCG JSON parser
python cli/run_tcg_parser.py path/to/log.json

# PCR7 measured boot digest calculator
python cli/pcr7_measured_boot.py --cert path/to/cert.der --verbose

# BitLocker metadata parser
python cli/bitlocker_parser_cli.py metadata-secboot
```

### As a Library

```python
# Make sure you're in the TpmEventLog directory or have it in your Python path
import sys
import os
sys.path.append('/path/to/TpmEventLog')

# Parse a YAML log file
from TpmEventLog.parsers.parser import EventLogParser
from TpmEventLog.database.database import EventLogDatabase

parser = EventLogParser("path/to/log.yaml")
event_log = parser.parse()
database = EventLogDatabase()
log_id = database.add_event_log(parser)

# Parse a TCG JSON log file
from TpmEventLog.parsers.tcg_parser import TCGLogParser
from TpmEventLog.database.tcg_database_adapter import TcgDatabaseManager

parser = TCGLogParser("path/to/log.json")

# Calculate PCR7 digest for a certificate
from TpmEventLog.cli.pcr7_measured_boot import read_certificate, extract_signature_data_from_cert, measure_variable, OVMF_GUID

cert_data = read_certificate("path/to/cert.der")
sig_data = extract_signature_data_from_cert(cert_data)
digest, var_log = measure_variable(OVMF_GUID, sig_data)
print(f"Calculated hash: {digest.hex()}")

# Parse BitLocker metadata and extract TPM structures
from TpmEventLog.parsers.bitlocker_parser import parse_bitlocker_metadata

# Parse BitLocker metadata and save structures to the default output directory
structures = parse_bitlocker_metadata("data/metadata/metadata-secboot")

# Parse BitLocker metadata and save structures to a custom output directory
structures = parse_bitlocker_metadata("data/metadata/metadata-secboot", "output/metadata-keys")

# Access the extracted TPM structures
tpm2b_public = structures.get('TPM2B_PUBLIC')
tpm2b_private = structures.get('TPM2B_PRIVATE')
```

## Code Flow

1. **Parsing**: Raw log files are parsed into structured data objects
   - `parser.py` and `tcg_parser.py` handle different log formats
   - `bitlocker_parser.py` extracts TPM structures from BitLocker metadata
   - Parsed data is represented using the core model classes

2. **Database Management**: Parsed logs are stored in a database
   - `database.py` handles database operations
   - `tcg_database_adapter.py` adapts TCG logs to the database format

## Development

To run tests:

```bash
cd TpmEventLog
python -m unittest discover -s tests
```

## Dependencies

- PyYAML: `pip install pyyaml`

## Database Structure

The database is organized as follows:

```json
{
  "metadata": {
    "created_at": "timestamp",
    "last_updated": "timestamp",
    "version": "1.1.0"
  },
  "sources": {
    "log_id_1": {
      "source_file": "eventlogFedora.",
      "parsed_at": "timestamp",
      "version": 1,
      "event_count": 100,
      "sha256_event_count": 90
    },
    "log_id_2": {
      /* another source */
    }
  },
  "pcrs": {
    "0": {
      "index": 0,
      "events": {
        "1": {  // Event number as key
          "event_num": 1,
          "sources": {
            "log_id_1": {
              "source_file": "eventlogFedora.",
              "event_type": "EV_S_CRTM_VERSION",  // Event type at source level
              "event_size": 2,
              "sha256_digest": "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
              "event_data": {"Event": "0000"}
            },
            "log_id_2": {
              /* Same event from another source */
            }
          }
        }
      },
      "summary": {
        "log_id_1": {
          "source_file": "eventlogFedora.",
          "calculated_value": "extended_value_hash",
          "event_count": 15
        }
      }
    }
  }
}
```

This structure allows for easy comparison of the same event across different log sources.

## PCR Extension Commands

This tool also allows you to use the TPM ESAPI to perform PCR extension operations based on event data in summary files.

### Requirements

- Python 3.6+
- tpm2-pytss library (`pip install tpm2-pytss`)
- A physical TPM or software TPM (like IBM's SWTPM) accessible via a TCTI connection

### Usage

```bash
# Extend PCR using events from a summary file (stops at EV_SEPARATOR)
python main.py extend output/pcr7_source_12345678_summary.json

# Extend PCR up to a specific event number (ignores EV_SEPARATOR events)
python main.py extend output/pcr7_source_12345678_summary.json --max-event 10

# Attempt to reset the PCR before extending (only works for PCRs 16-23)
python main.py extend output/pcr7_source_12345678_summary.json --reset

# Specify a custom TCTI connection string for connecting to the TPM
python main.py extend output/pcr7_source_12345678_summary.json --tcti "swtpm:host=localhost,port=2321"
```

This command will:
1. Read the PCR index and events from the summary file
2. Connect to the TPM using the provided TCTI connection (or default if none specified)
3. Optionally reset the PCR (if requested and supported)
4. Sequentially extend the PCR with each event's digest
5. Report the initial and final PCR values

By default, the command will stop after processing an EV_SEPARATOR event. When using the --max-event option, EV_SEPARATOR events are ignored and the command will extend up to the specified event number.

### TCTI Connection Examples

- System TPM: Leave empty to use default `""` 
- Software TPM (SWTPM): `