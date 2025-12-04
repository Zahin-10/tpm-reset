import sys
import struct
import subprocess
import tpm2_pytss
import argparse
from typing import Optional, Sequence, List

def convert_hex_to_binary(hexbin, output_file):
    # Convert the hex string to raw binary
    with open(output_file, "wb") as bin_file:
        bin_file.write(hexbin)
    print(f"[+] Saved binary data to {output_file}")


def parse_tpm2b_structure(data, offset):
    """
    Parses a TPM2B structure (TPM2B_PUBLIC or TPM2B_PRIVATE).

    Args:
        data (bytes): The binary data containing the TPM2B structure.
        offset (int): The current offset in the data.

    Returns:
        tuple: A tuple containing the parsed TPM2B structure data and the new offset.
    """
    if offset + 2 > len(data):
        print("Insufficient data for TPM2B size field.")
        sys.exit(1)

    # TPM2B structures have a 2-byte size field
    size = struct.unpack_from('>H', data, offset)[0]
    

    if offset + size > len(data):
        print(f"Insufficient data for TPM2B structure. Expected size: {size}, Available: {len(data) - offset}")
        sys.exit(1)
    # Extract the structure data
    end_offset = offset + size + 2
    structure_data = data[offset:end_offset]
    offset += size
    offset += 2
    return structure_data, offset

def strip_info(s):
    return s.split('[INFO]')[1].strip().strip()[10:].replace('-', ' ')


def extract_payload(trace):
    lines = trace.split('\n')
    print("Locating 'ENTRY TYPE VMK' with 'TPM Protection'...")

    # Find a VMK entry that has TPM Protection
    vmk_line = -1
    
    for i, line in enumerate(lines):
        if "ENTRY TYPE VMK" in line:
            # Found a VMK entry, check if it's followed by TPM Protection
            for j in range(i, min(i + 30, len(lines))):  # Look within next 30 lines
                if "UTF-16 string: 'TPM Protection'" in lines[j]:
                    print(f"Found TPM-protected VMK entry at line {i + 1}")
                    vmk_line = i
                    break
            if vmk_line != -1:
                break
    
    if vmk_line == -1:
        print("Could not find 'ENTRY TYPE VMK' with 'TPM Protection'. Aborting.")
        return None

    print(f"'ENTRY TYPE VMK' found on line {vmk_line + 1}:")
    print("Selecting payload lines...")
    
    # Using the original logic: the payload is at a fixed offset from VMK line
    # Instead of +26, use +26 from the VMK line where TPM Protection was found
    payload_start = vmk_line + 26
    
    # Original extraction logic
    payload_lines = []
    for j in range(payload_start, len(lines)):
        clean_line = strip_info(lines[j]).replace(' ', "")

        if "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" in lines[j]:
            break

        payload_lines.append(clean_line.strip())

    payload_line = ''.join(payload_lines)
    return payload_line

def extract_tpm2_blob_from_luks(luks_header_output):
    """
    Extract the tpm2-blob from LUKS header information.
    
    Args:
        luks_header_output (str): The output from 'cryptsetup luksDump' command
        
    Returns:
        str: The extracted tpm2-blob as a continuous hex string without spaces
    """
    lines = luks_header_output.split('\n')
    
    # Find the tpm2-blob section
    blob_start_line = -1
    for i, line in enumerate(lines):
        if "tpm2-blob:" in line:
            blob_start_line = i
            break
    
    if blob_start_line == -1:
        print("Could not find 'tpm2-blob:' in the LUKS header. Aborting.")
        return None
    
    # Extract the blob data
    blob_lines = []
    current_line = blob_start_line
    
    # Get the first part from the line containing "tpm2-blob:"
    first_part = lines[current_line].split("tpm2-blob:")[1].strip()
    blob_lines.append(first_part)
    
    # Continue collecting indented lines that are part of the blob
    current_line += 1
    while current_line < len(lines):
        line = lines[current_line].strip()
        if line.strip() == "Keyslot:    1":
            break
        # Check if the line starts with indentation and contains hex values
        if line.startswith("            ") or any(c in line for c in "0123456789abcdef"):
            blob_lines.append(line.strip())
            current_line += 1
        else:
            # We've reached the end of the blob section
            break
    
    # Join all parts and remove spaces
    blob_data = ' '.join(blob_lines)
    blob_data = blob_data.replace(' ', '')
    
    return blob_data

def parse_args(args):
    parser = argparse.ArgumentParser(description="A script that accepts two arguments")
    parser.add_argument("--metadata", help="Contents of the metadata header information")
    parser.add_argument("--type", help="Metadata source type for extracting sealed object")
    return parser.parse_args(args)

def main(args: List[str] = None):
    # Check if a file path is provided as a command-line argument
    args = parse_args(args)
    file_path = args.metadata
    source_type = args.type

    try:
        with open(file_path, 'r') as f:
            trace = f.read()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        print("Usage: python parse-bitlocker-metadata.py [file_path]")
        sys.exit(1)
    if source_type == "linux":
        payload = extract_tpm2_blob_from_luks(trace)
    else:
        payload = extract_payload(trace)
    if payload is None:
        sys.exit(1)
    try:
        binary_data = bytes.fromhex(payload)
    except ValueError as e:
        print(f"Error converting payload to binary: {e}")
        # Try removing 'x' prefix if present
        if payload.startswith('x'):
            print("Trying to remove 'x' prefix from payload...")
            payload = payload[1:]
            try:
                binary_data = bytes.fromhex(payload)
                print("Successfully converted payload after removing 'x' prefix")
            except ValueError as e2:
                print(f"Still error after removing 'x' prefix: {e2}")
                sys.exit(1)
        else:
            sys.exit(1)

    offset = 0
    structures = {}

    # Parse TPM2B_PUBLIC
    private_data, offset = parse_tpm2b_structure(binary_data, offset)
    structures['TPM2B_PRIVATE'] = private_data

    # Parse TPM2B_PRIVATE
    public_data, offset = parse_tpm2b_structure(binary_data, offset)
    structures['TPM2B_PUBLIC'] = public_data
    if source_type == "linux":
        sealedObjectPath = "data/linux/"
    else:
        sealedObjectPath = "data/windows/"
    convert_hex_to_binary(structures['TPM2B_PUBLIC'], sealedObjectPath + "TPM2B_PUBLIC.bin")
    convert_hex_to_binary(structures['TPM2B_PRIVATE'], sealedObjectPath + "TPM2B_PRIVATE.bin")

if __name__ == "__main__":
    main()