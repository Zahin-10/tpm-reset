# TPM2_PCR_Extend_Command_Parser_CSV.py

import csv
import sys

def parse_pcr_extend_command(hex_string):
    # Remove any leading/trailing whitespace and double quotes
    hex_string = hex_string.strip().strip('"')

    packet_bytes = bytes.fromhex(hex_string)
    offset = 0

    # Read tag (2 bytes)
    tag = int.from_bytes(packet_bytes[offset:offset+2], 'big')
    offset += 2

    if tag not in [0x8001, 0x8002]:
        raise ValueError(f"Unsupported tag: 0x{tag:04x}")

    # Read command size (4 bytes)
    command_size = int.from_bytes(packet_bytes[offset:offset+4], 'big')
    offset += 4

    # Read command code (4 bytes)
    command_code = int.from_bytes(packet_bytes[offset:offset+4], 'big')
    offset += 4

    if command_code != 0x00000182:
        raise ValueError(f"Unsupported command code: 0x{command_code:08x}")

    # Read handle (4 bytes)
    pcr_handle = int.from_bytes(packet_bytes[offset:offset+4], 'big')
    offset += 4

    # Read authorization area size (4 bytes)
    auth_area_size = int.from_bytes(packet_bytes[offset:offset+4], 'big')
    offset += 4

    # Skip the authorization area
    offset += auth_area_size

    # Read digest count (UINT32)
    count = int.from_bytes(packet_bytes[offset:offset+4], 'big')
    offset += 4

    hash_alg_map = {
        0x0004: ('sha1', 20),
        0x000B: ('sha256', 32),
        0x000C: ('sha384', 48),
        0x000D: ('sha512', 64),
    }

    digests = []

    for _ in range(count):
        # Read hash algorithm identifier (2 bytes)
        hash_alg = int.from_bytes(packet_bytes[offset:offset+2], 'big')
        offset += 2

        if hash_alg not in hash_alg_map:
            raise ValueError(f"Unknown hash algorithm: 0x{hash_alg:04x}")

        hash_name, digest_size = hash_alg_map[hash_alg]

        # Read digest value
        digest_value = packet_bytes[offset:offset+digest_size]
        offset += digest_size

        # Store the digest
        digests.append((hash_name, digest_value.hex()))

    # Generate the tpm2_pcrextend command
    pcr_index = pcr_handle
    digest_entries = [f"{hash_name}={digest_hex}" for hash_name, digest_hex in digests]
    command = f"tpm2_pcrextend --tcti=\"swtpm:host=localhost,port=2321\" {pcr_index}:" + ','.join(digest_entries)

    return command

def process_csv(output_csv_path):
    input_csv_path = "data/windows/input.csv"
    with open(input_csv_path, 'r', newline='') as csvfile_in, open(output_csv_path, 'w', newline='') as csvfile_out:
        reader = csv.reader(csvfile_in)
        writer = csv.writer(csvfile_out)

        # Write header for the output CSV file
        #writer.writerow(['TPM2_PCRExtend_Command'])

        for row in reader:
            if not row:
                continue  # Skip empty rows
            hex_string = row[0]
            try:
                command = parse_pcr_extend_command(hex_string)
                writer.writerow([command])
            except Exception as e:
                print(f"Error processing row: {hex_string}\n{e}")
                writer.writerow([hex_string, f"Error: {e}"])

if __name__ == "__main__":
    output_csv_path = "data/windows/output_command.csv"

    process_csv(output_csv_path)
    print(f"Processing complete. Output saved to '{output_csv_path}'.")