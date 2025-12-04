"""
TPM Event Log Parser Main Entry Point

This script provides a unified entry point to the different parsers
in the TpmEventLog package. It can parse both YAML and TCG JSON format logs
and add them to the event log database.

Usage:
    cd TpmEventLog
    python main.py yaml [log_file] [--db DB_FILE] [--store-raw-events]
    python main.py tcg [log_file] [--db DB_FILE] [--verbose] [--store-raw-events]
    python main.py analyse --db DB_FILE [--pcr PCR_INDEX] [options]
    python main.py summary --db DB_FILE [--pcr PCR_INDEX]
    python main.py extend SUMMARY_FILE [--max-event MAX_EVENT] [--tcti TCTI_CONNECTION] [--reset]
    python main.py pcr7-digest --cert CERT_PATH [--guid GUID] [--expected DIGEST] [--save FILE_PATH] [--verbose]
    python main.py parse-bitlocker-vmk METADATA_FILE [--output-dir OUTPUT_DIR]
    python main.py extract-linux-eventlog [--input INPUT_FILE] [--output OUTPUT_FILE] [--db DB_FILE] [--store-raw-events]
    python main.py replay-pcr-events --config path/to/your_config.yaml
    
Example:
    # Parse logs and add to database
    python main.py yaml data/tpm_log.yaml --db db/logs.json
    python main.py tcg data/TCGlog_SRTMCurrent.json --db db/logs.json
    
    # Parse logs with raw event data (increases database size)
    python main.py yaml data/tpm_log.yaml --db db/logs.json --store-raw-events
    python main.py tcg data/TCGlog_SRTMCurrent.json --db db/logs.json --store-raw-events
    
    # Analyse events from the database
    python main.py analyse --db db/logs.json --pcr 7
    python main.py analyse --db db/logs.json --list-sources
    python main.py analyse --db db/logs.json --pcr 7 --event-type EV_SEPARATOR
    
    # Generate summary for a source
    python main.py summary --db db/logs.json --pcr 7
    
    # Extend PCR using summary file (stops at EV_SEPARATOR)
    python main.py extend output/pcr7_source_12345678_summary.json
    
    # Extend PCR using summary file with specific TCTI connection
    python main.py extend output/pcr7_source_12345678_summary.json --tcti "swtpm:host=localhost,port=2321"
    
    # Extend PCR up to a specific event number (ignores EV_SEPARATOR)
    python main.py extend output/pcr7_source_12345678_summary.json --max-event 10
    
    # Calculate PCR7 digest for a certificate
    python main.py pcr7-digest --cert path/to/cert.der --expected "expected_digest_value"
    
    # Parse BitLocker metadata and extract TPM structures
    python main.py parse-bitlocker-vmk metadata-secboot --output-dir output/metadata
    
    # Extract Linux TPM event log using tpm2_eventlog
    python main.py extract-linux-eventlog --output data/linux_tpm_eventlog.yaml
    python main.py extract-linux-eventlog --input /sys/kernel/security/tpm0/binary_bios_measurements --output data/linux_tpm_eventlog.yaml
    python main.py extract-linux-eventlog --output data/linux_tpm_eventlog.yaml --db db/logs.json
    
    # Replay PCR Events sequence command
    python main.py replay-pcr-events --config path/to/your_config.yaml
    
Note:
    When executing a comparison, sources are automatically selected from the database if
    not explicitly specified. A side-by-side comparison is displayed and the results are 
    automatically saved to a JSON file in the 'output' directory.
    
    The summary command generates a detailed report for a single source, including
    event details, PCR calculation steps, and event type distribution. The summary
    is also saved as a JSON file in the 'output' directory.
    
    When adding a new log from the same source file, it will replace any existing
    log from that source to prevent duplicate entries.
    
    By default, the extend command will stop after processing an EV_SEPARATOR event.
    When using the --max-event option, EV_SEPARATOR events are ignored and the command
    will extend up to the specified event number.
    
    BitLocker metadata files should be placed in the data/metadata directory.
    
    The extract-linux-eventlog command uses tpm2_eventlog to parse the binary TPM event log 
    on Linux systems. By default, it reads from /sys/kernel/security/tpm0/binary_bios_measurements
    and outputs the YAML format to the data directory.
"""

import sys
import os
import argparse
import subprocess
import datetime
from typing import List, Optional

# Get the current directory of this script
current_dir = os.path.dirname(os.path.abspath(__file__))

# Import directly from the cli scripts instead of through the cli package
sys.path.append(os.path.join(current_dir, 'cli'))
from cli.tpm_parser import main as yaml_main
from cli.run_tcg_parser import main as tcg_main
from cli.analyse import main as compare_main
from cli.summary import main as summary_main
from cli.pcr_extend import main as extend_main
from cli.pcr7_measured_boot import main as pcr7_digest_main
from cli.bitlocker_parser_cli import main as bitlocker_main

# Import yaml for config file parsing
import yaml

# Import for type hinting
from database.database import EventLogDatabase


def extract_linux_eventlog(input_file: str, output_file: str, db_file: Optional[str] = None, store_raw_events: bool = False):
    """
    Extract TPM event log from Linux TPM binary measurements file using tpm2_eventlog
    
    Args:
        input_file: Path to the binary measurements file
        output_file: Path to save the YAML output
        db_file: Optional database file to add the parsed log to
        store_raw_events: Whether to store raw event data in the database
    """
    # Ensure data directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
        # Run tpm2_eventlog command
        result = subprocess.run(['tpm2_eventlog', input_file], 
                               capture_output=True, text=True, check=True)
        
        # Save the YAML output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
        
        print(f"TPM event log successfully extracted and saved to {output_file}")
        
        # If database file is provided, add the extracted log to it
        if db_file:
            # Backup sys.argv to restore later
            sys_argv_backup = sys.argv
            # Create new argv for the YAML parser
            yaml_args = ['tpm_parser.py', output_file, '-d', db_file]
            if store_raw_events:
                yaml_args.append('--store-raw-events')
            sys.argv = yaml_args
            yaml_main()
            # Restore original sys.argv
            sys.argv = sys_argv_backup
            
    except subprocess.CalledProcessError as e:
        print(f"Error running tpm2_eventlog: {e}")
        print(f"stderr: {e.stderr}")
        sys.exit(1)
    except FileNotFoundError:
        print("Error: tpm2_eventlog command not found. Please ensure tpm2-tools is installed.")
        sys.exit(1)


def _step_parse_log(config: dict, db_file: str) -> Optional[str]:
    """Helper function for Step 1: Parse Log."""
    print("\n--- Running Step 1: Parse Log ---")
    log_parser_type = config.get('log_parser')
    log_file_path = config.get('log_file')
    store_raw = config.get('store_raw_events', False)
    source_log_file = None

    if not log_parser_type or not log_file_path:
        print("Error: 'log_parser' (tcg/yaml) and 'log_file' must be specified in config for Step 1.")
        sys.exit(1)

    sys_argv_backup = sys.argv
    try:
        if log_parser_type.lower() == 'yaml':
            print(f"Parsing YAML log: {log_file_path}")
            yaml_args = ['tpm_parser.py', log_file_path, '-d', db_file]
            if store_raw:
                yaml_args.append('--store-raw-events')
            sys.argv = yaml_args
            yaml_main()
            source_log_file = log_file_path
            print(f"YAML log parsed successfully. DB: {db_file}")
        elif log_parser_type.lower() == 'tcg':
            print(f"Parsing TCG log: {log_file_path}")
            tcg_args = ['run_tcg_parser.py', log_file_path, '--db', db_file]
            if store_raw:
                tcg_args.append('--store-raw-events')
            sys.argv = tcg_args
            tcg_main()
            source_log_file = log_file_path
            print(f"TCG log parsed successfully. DB: {db_file}")
        else:
            print(f"Error: Invalid 'log_parser' type '{log_parser_type}'. Must be 'yaml' or 'tcg'.")
            sys.exit(1)
        return source_log_file
    except SystemExit as e:
        print(f"Log parsing step (Step 1) exited with code {e.code}. Check for errors above.")
        sys.exit(1) # Exit if parsing fails
    except Exception as e:
        print(f"An error occurred during log parsing (Step 1): {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        sys.argv = sys_argv_backup
    return None # Should not be reached if exiting on error


def _step_create_summary(config: dict, db_file: str, source_log_file: str) -> tuple[Optional[str], Optional[str]]:
    """Helper function for Step 2: Create Summary."""
    print("\n--- Running Step 2: Create Summary ---")
    summary_pcr_index = config.get('summary_pcr', 7)
    source_id_for_summary = None
    summary_file_path = None

    if not source_log_file:
        print("Error: source_log_file not provided to _step_create_summary. Aborting summary.")
        sys.exit(1)

    # Load the database to find the source_id
    try:
        db = EventLogDatabase(db_file) # Ensure EventLogDatabase is imported
        all_source_ids = db.get_source_ids()
        found_source_id = None
        for sid in all_source_ids:
            source_details = db.get_source_by_id(sid)
            if source_details and os.path.abspath(source_details.get('source_file', '')) == os.path.abspath(source_log_file):
                found_source_id = sid
                break
        
        if not found_source_id:
            if len(all_source_ids) == 1:
                print(f"Warning: Could not directly match source_file '{source_log_file}'. Using the only available source: {all_source_ids[0]}")
                found_source_id = all_source_ids[0]
            else:
                print(f"Error: Could not find a source_id in database '{db_file}' that matches parsed log '{source_log_file}'.")
                print(f"Available sources in DB: {all_source_ids}")
                sys.exit(1)
        source_id_for_summary = found_source_id
        print(f"Determined source_id for summary: {source_id_for_summary}")

    except Exception as e:
        print(f"Error accessing database '{db_file}' to find source_id for summary (Step 2): {e}")
        sys.exit(1)

    sys_argv_backup = sys.argv
    try:
        os.makedirs("output", exist_ok=True)
        summary_file_name = f"pcr{summary_pcr_index}_source_{source_id_for_summary[:8]}_summary.json"
        
        summary_args = ['summary.py', '--db', db_file, '--pcr', str(summary_pcr_index), '--source', source_id_for_summary]
        sys.argv = summary_args
        print(f"Calling summary_main with args: {sys.argv}")
        summary_main() 
        
        summary_file_path = os.path.join("output", summary_file_name)
        print(f"Summary generation step called. Expected summary file: {summary_file_path}")
        if not os.path.exists(summary_file_path):
             print(f"Warning: Summary file {summary_file_path} was not created. Check summary script output.")
        
        return source_id_for_summary, summary_file_path
    except SystemExit as e:
        print(f"Summary generation (Step 2) exited with code {e.code}. Check for errors above.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during summary generation (Step 2): {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        sys.argv = sys_argv_backup
    return None, None # Should not be reached


def _step_extend_pcr(config: dict, summary_file_path: str) -> None:
    """Helper function for Step 3: Extend PCR."""
    print("\n--- Running Step 3: Extend PCR ---")
    extend_tcti = config.get('extend_tcti')
    extend_max_event = config.get('extend_max_event')
    extend_reset_pcr = config.get('extend_reset_pcr', False)
    extend_cert_path = config.get('extend_cert_path')
    # Use a single GUID from config for PCR7 operations
    pcr7_uefi_guid_for_extend = config.get('pcr7_uefi_guid') 

    if not summary_file_path or not os.path.exists(summary_file_path):
        print(f"Error: Summary file '{summary_file_path}' not found or not created. Cannot proceed to extend (Step 3).")
        sys.exit(1)
    # TCTI might be optional for some TPM setups, but often required.
    if not extend_tcti:
        print("Warning: 'extend_tcti' not specified in config. Extend command might default or fail if TCTI is required.")

    sys_argv_backup = sys.argv
    try:
        extend_args = ['pcr_extend.py', summary_file_path]
        if extend_tcti:
            extend_args.extend(['--tcti', extend_tcti])
        if extend_max_event is not None:
            extend_args.extend(['--max-event', str(extend_max_event)])
        if extend_reset_pcr:
            extend_args.append('--reset')
        if extend_cert_path:
            extend_args.extend(['--cert', extend_cert_path])
        if pcr7_uefi_guid_for_extend:
            extend_args.extend(['--pcr7-guid', pcr7_uefi_guid_for_extend])
        
        sys.argv = extend_args
        print(f"Calling extend_main with args: {sys.argv}")
        extend_main()
        print("Extend PCR (Step 3) completed.")
    except SystemExit as e:
        print(f"Extend PCR step (Step 3) exited with code {e.code}. Check for errors above.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred during PCR extend (Step 3): {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        sys.argv = sys_argv_backup


def _step_create_pcr7_digest(config: dict) -> None:
    """Helper function for Step 4: Create PCR7 Digest."""
    print("\n--- Running Step 4: Create PCR7 Digest ---")
    pcr7_cert_path = config.get('pcr7_digest_cert')
    # Use the same single GUID from config for PCR7 operations
    pcr7_uefi_guid_for_digest = config.get('pcr7_uefi_guid') 
    pcr7_expected_digest = config.get('pcr7_digest_expected')
    pcr7_save_path = config.get('pcr7_digest_save_path')
    pcr7_verbose = config.get('pcr7_digest_verbose', False)

    if not pcr7_cert_path:
        print("Skipping Step 4 (Create PCR7 Digest): 'pcr7_digest_cert' not specified in config.")
        return # This step is optional

    sys_argv_backup = sys.argv
    try:
        pcr7_args = ['pcr7_measured_boot.py', '--cert', pcr7_cert_path]
        if pcr7_uefi_guid_for_digest:
            pcr7_args.extend(['--guid', pcr7_uefi_guid_for_digest])
        if pcr7_expected_digest:
            pcr7_args.extend(['--expected', pcr7_expected_digest])
        if pcr7_save_path:
            if os.path.dirname(pcr7_save_path):
                 os.makedirs(os.path.dirname(pcr7_save_path), exist_ok=True)
            pcr7_args.extend(['--save', pcr7_save_path])
        if pcr7_verbose:
            pcr7_args.append('--verbose')
        
        sys.argv = pcr7_args
        print(f"Calling pcr7_digest_main with args: {sys.argv}")
        pcr7_digest_main()
        print("PCR7 Digest creation (Step 4) completed.")
    except SystemExit as e:
        print(f"PCR7 Digest creation step (Step 4) exited with code {e.code}. Check for errors.")
        print("Warning: PCR7 Digest creation failed. Continuing with next steps.") # Non-fatal
    except Exception as e:
        print(f"An error occurred during PCR7 Digest creation (Step 4): {e}")
        import traceback
        traceback.print_exc()
        print("Warning: PCR7 Digest creation failed. Continuing with next steps.") # Non-fatal
    finally:
        sys.argv = sys_argv_backup


def _step_parse_bitlocker_vmk(config: dict) -> None:
    """Helper function for Step 5: Parse BitLocker VMK."""
    print("\n--- Running Step 5: Parse BitLocker VMK ---")
    bitlocker_metadata = config.get('bitlocker_metadata_file')
    bitlocker_output = config.get('bitlocker_output_dir', 'output/metadata_auto')

    if not bitlocker_metadata:
        print("Skipping Step 5 (Parse BitLocker VMK): 'bitlocker_metadata_file' not specified in config.")
        return # This step is optional

    os.makedirs(bitlocker_output, exist_ok=True)
    
    sys_argv_backup = sys.argv
    try:
        bitlocker_args = ['bitlocker_parser_cli.py', bitlocker_metadata, '--output-dir', bitlocker_output]
        sys.argv = bitlocker_args
        print(f"Calling bitlocker_main with args: {sys.argv}")
        bitlocker_main()
        print("BitLocker VMK parsing (Step 5) completed.")
    except SystemExit as e:
        print(f"BitLocker VMK parsing step (Step 5) exited with code {e.code}. Check for errors.")
        print("Warning: BitLocker VMK parsing failed. Sequence will continue if possible.") # Non-fatal
    except Exception as e:
        print(f"An error occurred during BitLocker VMK parsing (Step 5): {e}")
        import traceback
        traceback.print_exc()
        print("Warning: BitLocker VMK parsing failed. Sequence will continue if possible.") # Non-fatal
    finally:
        sys.argv = sys_argv_backup


def run_replay_pcr_events_sequence(config_file: str):
    """
    Runs a predefined sequence of TPM event log operations based on a config file.
    This sequence typically involves parsing a log, summarizing a PCR, extending it,
    and calculating PCR7 digest for UEFI Secure Boot variables.
    """
    try:
        with open(config_file, 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Configuration file '{config_file}' not found.")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing configuration file '{config_file}': {e}")
        sys.exit(1)

    print(f"Automated sequence started with config from '{config_file}'")

    # --- Common variables --- 
    db_file = config.get('db_file', 'db/logs.json')
    # Ensure db directory exists
    os.makedirs(os.path.dirname(db_file), exist_ok=True)

    source_log_file = None # To store the path of the initial log for summary source selection
    source_id_for_summary = None # To store the determined source_id
    summary_file_path = None # To store the path of the generated summary file

    # --- Step 1: Parse Log (YAML or TCG) --- 
    source_log_file = _step_parse_log(config, db_file)
    if not source_log_file:
        # _step_parse_log should sys.exit on failure, but as a safeguard:
        print("Error: Log parsing (Step 1) failed to return a source log file. Aborting sequence.")
        sys.exit(1)

    # --- Step 2: Create Summary for PCR7 (or configured PCR) ---
    source_id_for_summary, summary_file_path = _step_create_summary(config, db_file, source_log_file)
    if not summary_file_path: # Check if summary_file_path was successfully created
        print("Error: Summary creation (Step 2) failed to return a summary file path. Aborting sequence.")
        sys.exit(1)

    # --- Step 3: Run Extend Command ---
    _step_extend_pcr(config, summary_file_path)

    # --- Step 4: Create PCR7 Digest from Certificate ---
    _step_create_pcr7_digest(config)

    # --- Step 5: Parse BitLocker VMK ---
    _step_parse_bitlocker_vmk(config)
    
    print("\n--- Replay sequence finished. ---")


def main(args: List[str] = None):
    """
    Main entry point for the TPM Event Log Parser.
    
    Args:
        args: Command line arguments (defaults to sys.argv if None)
    """
    parser = argparse.ArgumentParser(
        description='TPM Event Log Parser and Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python main.py yaml data/tpm_log.yaml --db db/logs.json
  python main.py tcg data/TCGlog_SRTMCurrent.json --db db/logs.json
  python main.py analyse --db db/logs.json --pcr 7
  python main.py summary --db db/logs.json --pcr 7
  python main.py extend output/pcr7_source_12345678_summary.json
  python main.py extend output/pcr7_source_12345678_summary.json --max-event 10
  python main.py pcr7-digest --cert path/to/cert.der --expected "expected_digest_value"
  python main.py parse-bitlocker-vmk metadata-secboot --output-dir output/metadata
  python main.py extract-linux-eventlog --output data/linux_tpm_eventlog.yaml
  python main.py replay-pcr-events --config path/to/your_config.yaml"""
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # YAML parser command
    yaml_parser = subparsers.add_parser('yaml', help='Parse a YAML format TPM event log')
    yaml_parser.add_argument('log_file', help='Path to the YAML log file')
    yaml_parser.add_argument('-d', '--db', help='Path to the database file')
    yaml_parser.add_argument('--store-raw-events', action='store_true', 
                           help='Store raw event data in the database (increases size)')
    
    # TCG parser command
    tcg_parser = subparsers.add_parser('tcg', help='Parse a TCG JSON format TPM event log')
    tcg_parser.add_argument('log_file', help='Path to the TCG JSON log file')
    tcg_parser.add_argument('-d', '--db', help='Path to the database file')
    tcg_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    tcg_parser.add_argument('--store-raw-events', action='store_true', 
                           help='Store raw event data in the database (increases size)')
    
    # Analyse command (previously extract/compare)
    analyse_parser = subparsers.add_parser('analyse', help='Analyse events and compare sources from the database')
    analyse_parser.add_argument('--db', required=True, help='Path to the database file')
    analyse_parser.add_argument('--pcr', type=int, help='PCR index to analyze')
    analyse_parser.add_argument('--source1', help='First source ID to compare')
    analyse_parser.add_argument('--source2', help='Second source ID to compare')
    analyse_parser.add_argument('--list-sources', action='store_true', help='List available sources')
    analyse_parser.add_argument('--list-pcrs', action='store_true', help='List available PCR indices')
    analyse_parser.add_argument('--list-event-types', action='store_true', 
                              help='List event types for a PCR index')
    analyse_parser.add_argument('--values', action='store_true', 
                              help='Display PCR values for all sources')
    
    # Summary command
    summary_parser = subparsers.add_parser('summary', help='Generate summary for a source')
    summary_parser.add_argument('--db', required=True, help='Path to the database file')
    summary_parser.add_argument('--pcr', type=int, help='PCR index to summarize')
    
    # Extend command
    extend_parser = subparsers.add_parser('extend', 
                                        help='Run PCR extend commands using ESAPI based on summary data')
    extend_parser.add_argument('summary_file', help='Path to the summary JSON file')
    extend_parser.add_argument('--max-event', type=int, 
                             help='Maximum event number to process (inclusive). When specified, EV_SEPARATOR events are ignored.')
    extend_parser.add_argument('--tcti', help='TCTI connection string (e.g., "swtpm:host=localhost,port=2321")')
    extend_parser.add_argument('--reset', action='store_true', 
                             help='Attempt to reset the PCR before extending (only works for PCRs 16-23)')
    extend_parser.add_argument('--cert', help='Path to certificate in DER format for PCR7 measured boot digest')
    
    # PCR7 Measured Boot Digest command
    pcr7_digest_parser = subparsers.add_parser('pcr7-digest', 
                                             help='Calculate PCR7 digest for UEFI Secure Boot variables')
    pcr7_digest_parser.add_argument('--cert', required=True, help='Path to certificate in DER format')
    pcr7_digest_parser.add_argument('--guid', help='Custom GUID to use (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)')
    pcr7_digest_parser.add_argument('--expected', help='Expected digest value to compare with')
    pcr7_digest_parser.add_argument('--save', help='Save the UEFI_VARIABLE_DATA structure to a file')
    pcr7_digest_parser.add_argument('--verbose', '-v', action='store_true', help='Show verbose output')
    
    # BitLocker parser command
    bitlocker_parser = subparsers.add_parser('parse-bitlocker-vmk', 
                                           help='Parse BitLocker metadata and extract TPM structures')
    bitlocker_parser.add_argument('metadata_file', help='Name of the BitLocker metadata file (in data/metadata directory)')
    bitlocker_parser.add_argument('--output-dir', '-o', default='output/metadata',
                                help='Directory to save extracted structures (default: output/metadata)')
    
    # Linux TPM event log extractor
    linux_eventlog_parser = subparsers.add_parser('extract-linux-eventlog',
                                                help='Extract TPM event log from Linux using tpm2_eventlog')
    linux_eventlog_parser.add_argument('--input', '-i',
                                     default='/sys/kernel/security/tpm0/binary_bios_measurements',
                                     help='Path to the binary measurements file (default: /sys/kernel/security/tpm0/binary_bios_measurements)')
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    linux_eventlog_parser.add_argument('--output', '-o',
                                     default=f'data/linux_tpm_eventlog_{timestamp}.yaml',
                                     help='Path to save the YAML output (default: data/linux_tpm_eventlog_<timestamp>.yaml)')
    linux_eventlog_parser.add_argument('--db', help='Path to the database file to add the parsed log to')
    linux_eventlog_parser.add_argument('--store-raw-events', action='store_true',
                                     help='Store raw event data in the database (increases size)')
    
    # Replay PCR Events sequence command
    replay_parser = subparsers.add_parser('replay-pcr-events', 
                                          help='Run a sequence of PCR-related commands automatically from a config file',
                                          epilog="Example config.yaml for replay-pcr-events:\n"
                                                 "  log_parser: tcg                              # tcg or yaml\n"
                                                 "  log_file: \"data/TCGlog_SRTMCurrent.json\"\n"
                                                 "  db_file: \"db/auto_logs.json\"\n"
                                                 "  store_raw_events: true\n"
                                                 "  summary_pcr: 7\n"
                                                 "  extend_tcti: \"swtpm:host=localhost,port=2321\"\n"
                                                 "  extend_cert_path: \"path/to/cert.der\"          # Optional, for extend's internal PCR7 calc\n"
                                                 "  pcr7_digest_cert: \"path/to/cert.der\"      # Optional for pcr7-digest step\n"
                                                 "  pcr7_uefi_guid: \"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx\" # Optional UEFI GUID for all PCR7 operations\n"
                                                 "  bitlocker_metadata_file: \"metadata-secboot\" # Optional, name in data/metadata\n"
                                                 "  bitlocker_output_dir: \"output/bitlocker_auto\" # Optional",
                                          formatter_class=argparse.RawDescriptionHelpFormatter)
    replay_parser.add_argument('--config', required=True, help='Path to the YAML configuration file for the replay sequence')
    
    if args is None:
        args = sys.argv[1:]
        
    args = parser.parse_args(args)
    
    if not args.command:
        parser.print_help()
        return
    
    if args.command == 'yaml':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the YAML parser
        yaml_args = ['tpm_parser.py', args.log_file]
        if args.db:
            yaml_args.extend(['-d', args.db])
        if args.store_raw_events:
            yaml_args.append('--store-raw-events')
        sys.argv = yaml_args
        yaml_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'tcg':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the TCG parser
        tcg_args = ['run_tcg_parser.py', args.log_file]
        if args.db:
            tcg_args.extend(['--db', args.db])
        if args.verbose:
            tcg_args.append('-v')
        if args.store_raw_events:
            tcg_args.append('--store-raw-events')
        sys.argv = tcg_args
        tcg_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'analyse':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the analyse tool
        analyse_args = ['analyse.py', '--db', args.db]
        if args.pcr is not None:
            analyse_args.extend(['--pcr', str(args.pcr)])
        if args.source1:
            analyse_args.extend(['--source1', args.source1])
        if args.source2:
            analyse_args.extend(['--source2', args.source2])
        if args.list_sources:
            analyse_args.append('--list-sources')
        if args.list_pcrs:
            analyse_args.append('--list-pcrs')
        if args.list_event_types:
            analyse_args.append('--list-event-types')
        if args.values:
            analyse_args.append('--pcr-values')
        
        sys.argv = analyse_args
        compare_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'summary':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the summary tool
        summary_args = ['summary.py', '--db', args.db]
        if args.pcr is not None:
            summary_args.extend(['--pcr', str(args.pcr)])
        sys.argv = summary_args
        summary_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'extend':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the extend tool
        extend_args = ['pcr_extend.py', args.summary_file]
        if args.max_event is not None:
            extend_args.extend(['--max-event', str(args.max_event)])
        if args.tcti:
            extend_args.extend(['--tcti', args.tcti])
        if args.reset:
            extend_args.append('--reset')
        if args.cert:
            extend_args.extend(['--cert', args.cert])
        sys.argv = extend_args
        extend_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'pcr7-digest':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the PCR7 digest tool
        pcr7_args = ['pcr7_measured_boot.py']
        if args.cert:
            pcr7_args.extend(['--cert', args.cert])
        if args.guid:
            pcr7_args.extend(['--guid', args.guid])
        if args.expected:
            pcr7_args.extend(['--expected', args.expected])
        if args.save:
            pcr7_args.extend(['--save', args.save])
        if args.verbose:
            pcr7_args.append('--verbose')
        sys.argv = pcr7_args
        pcr7_digest_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'parse-bitlocker-vmk':
        # Backup sys.argv to restore later
        sys_argv_backup = sys.argv
        # Create new argv for the BitLocker parser
        bitlocker_args = ['bitlocker_parser_cli.py', args.metadata_file]
        if args.output_dir:
            bitlocker_args.extend(['--output-dir', args.output_dir])
        sys.argv = bitlocker_args
        bitlocker_main()
        # Restore original sys.argv
        sys.argv = sys_argv_backup
    
    elif args.command == 'extract-linux-eventlog':
        extract_linux_eventlog(
            input_file=args.input,
            output_file=args.output,
            db_file=args.db,
            store_raw_events=args.store_raw_events
        )
    
    elif args.command == 'replay-pcr-events':
        run_replay_pcr_events_sequence(config_file=args.config)


if __name__ == '__main__':
    # Make script executable from within the TpmEventLog directory
    sys.exit(main()) 