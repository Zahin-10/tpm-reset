#!/usr/bin/env python3
import sys
import re
import subprocess
import hashlib
import binascii
from pathlib import Path
# from Crypto.Cipher import AES
from tpm2_pytss import ESAPI
from tpm2_pytss.constants import TPM2_ALG
import csv

class LUKSHeader:
    """
    Object to retrieve and parse the LUKS header.
    Uses cryptsetup to dump the header and regex to parse key parameters.
    """
    def __init__(self, device_path: str):
        self.device_path = device_path
        self.header_dump = None
        self.header_info = {}

    def read_header(self) -> str:
        try:
            self.header_dump = subprocess.check_output(
                ['sudo', 'cryptsetup', 'luksDump', self.device_path],
                text=True
            )
            return self.header_dump
        except subprocess.CalledProcessError as e:
            print(f"Error reading LUKS header: {e}")
            sys.exit(1)

    def parse_header(self) -> dict:
        # Extract keyslot offset, keyslot length, AF stripes and PBKDF2 salt.
        # Look for Keyslots section and parse values
        keyslot_section = re.search(r'Keyslots:.*?(?=\n\n|\Z)', self.header_dump, re.DOTALL)
        if not keyslot_section:
            print("Error: Could not find Keyslots section")
            sys.exit(1)
            
        keyslot_text = keyslot_section.group(0)
        
        # Updated regex patterns to match exact format from header
        offset = re.search(r'Area offset:\s*(\d+)\s*\[bytes\]', keyslot_text)
        length = re.search(r'Area length:\s*(\d+)\s*\[bytes\]', keyslot_text)
        af = re.search(r'AF stripes:\s*(\d+)', keyslot_text)
        
        # Extract salt using pattern matching the exact format
        salt_pattern = r'Salt:\s+((?:[a-fA-F0-9]{2}\s+)+(?:[a-fA-F0-9]{2}(?:\s+|$))+)'
        salt_match = re.search(salt_pattern, keyslot_text)
        salt_hex = ''
        if salt_match:
            # Clean up salt value - remove all whitespace
            salt_hex = ''.join(salt_match.group(1).split())
        
        # Verify we have a valid hex string
        if salt_hex and not all(c in '0123456789abcdefABCDEF' for c in salt_hex):
            print(f"Warning: Invalid characters in salt hex string: {salt_hex}")
            salt_hex = ''
            
        # Debug prints
        print(f"\nDebug - Keyslot offset: {offset.group(1) if offset else 'None'}")
        print(f"Debug - Keyslot length: {length.group(1) if length else 'None'}")
        print(f"Debug - AF stripes: {af.group(1) if af else 'None'}")
        print(f"Debug - Extracted salt hex: {salt_hex}")
        
        self.header_info = {
            'keyslot_offset': int(offset.group(1)) if offset else None,
            'keyslot_length': int(length.group(1)) if length else None,
            'af_stripes': int(af.group(1)) if af else None,
            'pbkdf_salt': binascii.unhexlify(salt_hex) if salt_hex else None
        }
        return self.header_info

class LUKSKeyExtractor:
    """
    Extracts encrypted keyslot data from the device.
    Uses a dd command with the sector offset and length extracted from the header.
    """
    def __init__(self, device_path: str, header_info: dict, block_size: int = 1):
        self.device_path = device_path
        self.header_info = header_info
        self.block_size = block_size

    def extract_keyslot(self, output_file: str = 'keyslot.bin') -> str:
        keyslot_offset = self.header_info['keyslot_offset']
        keyslot_length = self.header_info['keyslot_length']
        blocks_offset = keyslot_offset // self.block_size
        blocks_count = (keyslot_length + self.block_size - 1) // self.block_size

        dd_command = [
            'sudo', 'dd',
            f'if={self.device_path}',
            f'of={output_file}',
            f'bs={self.block_size}',
            f'skip={blocks_offset}',
            f'count={blocks_count}'
        ]
        print(dd_command)
        try:
            subprocess.run(dd_command, check=True)
            return output_file
        except subprocess.CalledProcessError as e:
            print(f"Error extracting keyslot data: {e}")
            sys.exit(1)

    def read_keyslot(self, file_path: str = 'keyslot.bin') -> bytes:
        with open(file_path, 'rb') as f:
            return f.read()

class AntiForensicMerger:
    """
    Implements the anti-forensic merge process.
    Recombines key material stripes into the merged encrypted volume key.
    """
    @staticmethod
    def merge(data: bytes, stripes: int) -> bytes:
        segment_size = len(data) // stripes
        merged = bytes([
            sum(data[i * segment_size + j] for i in range(stripes)) % 256
            for j in range(segment_size)
        ])
        return merged

class TPMUnsealer:
    """
    Responsible for TPM-related operations.
    Loads a persistent TPM object from files and unseals the TPM key.
    Supports running PCR extend operations from a CSV file.
    """
    def __init__(self, tpm_device: str = '/dev/tpm0'):
        self.tpm_device = tpm_device
        self.hash_alg_map = {
            0x0004: ('sha1', 20),
            0x000B: ('sha256', 32),
            0x000C: ('sha384', 48),
            0x000D: ('sha512', 64),
        }

    def generate_input_csv(self, pcap_file: str, output_path: str = "data/linux/input.csv") -> bool:
        """Generate input CSV from pcap file using tshark."""
        try:
            # Find first Unseal command
            result = subprocess.run(
                ['tshark', '-r', pcap_file, '-Y', 'frame[72:4] == 00:00:01:5e',
                 '-T', 'fields', '-e', 'frame.number'],
                capture_output=True, text=True, check=True
            )
            unseal_frame = result.stdout.strip().split('\n')[0]
            if not unseal_frame:
                print("No Unseal command found in pcap file")
                return False

            # Create data/linux directory if it doesn't exist
            Path("data/linux").mkdir(parents=True, exist_ok=True)

            # Capture frames until first Unseal command
            subprocess.run(
                ['tshark', '-r', pcap_file,
                 '-Y', f'(frame[72:4] == 00:00:01:82) && (frame.number <= {unseal_frame})',
                 '-T', 'fields', '-E', 'header=n', '-E', 'separator=,', '-E', 'quote=d',
                 '-e', 'tcp.payload', '>', output_path],
                shell=True, check=True
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"Error generating input CSV: {e}")
            return False

    def parse_pcr_extend_command(self, hex_string: str) -> str:
        """Parse a single PCR extend command from hex string."""
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

        digests = []

        for _ in range(count):
            # Read hash algorithm identifier (2 bytes)
            hash_alg = int.from_bytes(packet_bytes[offset:offset+2], 'big')
            offset += 2

            if hash_alg not in self.hash_alg_map:
                raise ValueError(f"Unknown hash algorithm: 0x{hash_alg:04x}")

            hash_name, digest_size = self.hash_alg_map[hash_alg]

            # Read digest value
            digest_value = packet_bytes[offset:offset+digest_size]
            offset += digest_size

            # Store the digest
            digests.append((hash_name, digest_value.hex()))

        # Generate the tpm2_pcrextend command
        digest_entries = [f"{hash_name}={digest_hex}" for hash_name, digest_hex in digests]
        command = f"tpm2_pcrextend --tcti=\"swtpm:host=localhost,port=2321\" {pcr_handle}:" + ','.join(digest_entries)

        return command

    def process_csv(self, output_csv_path: str, pcap_file: str) -> bool:
        """
        Process TPM trace and generate PCR extend commands CSV.
        
        Args:
            output_csv_path: Path where to save the processed PCR extend commands
            pcap_file: Path to pcap file to generate input CSV from
        """
        try:
            # Generate input CSV from pcap
            input_csv_path = "data/linux/input.csv"
            if not self.generate_input_csv(pcap_file, input_csv_path):
                return False

            # Process the input CSV
            with open(input_csv_path, 'r', newline='') as csvfile_in, \
                 open(output_csv_path, 'w', newline='') as csvfile_out:
                reader = csv.reader(csvfile_in)
                writer = csv.writer(csvfile_out)

                for row in reader:
                    if not row:
                        continue  # Skip empty rows
                    hex_string = row[0]
                    try:
                        command = self.parse_pcr_extend_command(hex_string)
                        writer.writerow([command])
                    except Exception as e:
                        print(f"Error processing row: {hex_string}\n{e}")
                        writer.writerow([hex_string, f"Error: {e}"])

            # Clean up temporary input CSV
            Path(input_csv_path).unlink(missing_ok=True)
                
            return True
        except Exception as e:
            print(f"Error processing CSV: {e}")
            return False

    def run_pcr_extends(self, csv_filename: str) -> bool:
        """Run PCR extend commands from a CSV file locally."""
        print("\nExecuting PCR extends from CSV...")
        try:
            with open(csv_filename, newline='') as csvfile:
                reader = csv.reader(csvfile)
                for row in reader:
                    if not row:
                        continue
                    command = row[0].strip()
                    if not command:
                        continue

                    print(f"\nExecuting PCR extend command: {command}\n{'-' * 50}")
                    try:
                        result = subprocess.run(command, shell=True, check=True, 
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                             text=True)
                        print(result.stdout.strip())
                    except subprocess.CalledProcessError as e:
                        print(f"PCR extend command failed with exit code {e.returncode}")
                        print(e.stderr.strip())
                        return False
            return True
        except Exception as e:
            print(f"Failed to execute PCR extends: {e}")
            return False

    def unseal(self, pcr_csv: str = None) -> bytes:
        try:
            # Create data/linux directory if it doesn't exist
            Path("data/linux").mkdir(parents=True, exist_ok=True)

            # Use trace.pcapng from data/linux directory
            pcap_file = 'data/linux/trace.pcapng'
            if not Path(pcap_file).exists():
                raise Exception(f"TPM trace file not found at {pcap_file}")

            # Generate PCR extends CSV from trace
            pcr_csv = 'data/linux/pcr_extends.csv'
            if not self.process_csv(pcr_csv, pcap_file):
                raise Exception("Failed to process PCR trace")

            # Run PCR extends
            if not self.run_pcr_extends(pcr_csv):
                raise Exception("PCR extend operations failed")

            ctx = ESAPI(tcti=f'device:{self.tpm_device}')
            policy_session = ctx.start_auth_session(TPM2_ALG.SHA256, TPM2_ALG.POLICY)
            # Load persistent TPM object from files
            with open('data/linux/TPM2B_PUBLIC.bin', 'rb') as f:
                public_data = f.read()
            with open('data/linux/TPM2B_PRIVATE.bin', 'rb') as f:
                private_data = f.read()
            parent_handle = 0x81000001
            key_handle = ctx.load(parent_handle, private_data, public_data)
            unsealed = ctx.unseal(key_handle, policy_session)
            return unsealed
        except Exception as e:
            print(f"TPM unseal failed: {e}")
            sys.exit(1)

class LUKSVolumeKeyExtractor:
    """
    Coordinates the full extraction process:
      1. Retrieves and parses LUKS header information.
      2. Extracts keyslot data.
      3. Merges the anti-forensic stripes.
      4. Unseals a TPM-protected decryption key.
      5. Derives the AES key and decrypts the merged volume key.
    """
    def __init__(self, device_path: str, tpm_device: str = '/dev/tpm0'):
        self.device_path = device_path
        self.tpm_device = tpm_device
        self.header_info = None
        self.keyslot_file = 'data/linux/keyslot.bin'
        self.tpm_key = None
        self.volume_key = None

    def hex_dump(self, data: bytes) -> None:
        """Display data in hex dump format using xxd."""
        print("\nExtracted encrypted key from volume header (hex dump):")
        # Create a temporary file to hold the binary data
        temp_file = 'data/linux/temp_key.bin'
        try:
            with open(temp_file, 'wb') as f:
                f.write(data)
            
            # Use xxd to create the hex dump
            result = subprocess.run(['xxd', temp_file], 
                                 capture_output=True, text=True, check=True)
            print(result.stdout)
        finally:
            # Clean up temporary file
            Path(temp_file).unlink(missing_ok=True)

    def run(self) -> bytes:
        # Step 1: Get and parse LUKS header dump.
        header_obj = LUKSHeader(self.device_path)
        header_dump = header_obj.read_header()
        self.header_info = header_obj.parse_header()
        print("\nLUKS Header Information:")
        print("------------------------")
        for key, value in self.header_info.items():
            if key == 'pbkdf_salt':
                # Convert binary salt to hex for display
                print(f"{key}: {binascii.hexlify(value).decode() if value else None}")
            else:
                print(f"{key}: {value}")
        # Step 2: Extract keyslot using dd.
        key_extractor = LUKSKeyExtractor(self.device_path, self.header_info)
        key_extractor.extract_keyslot(self.keyslot_file)
        data = key_extractor.read_keyslot(self.keyslot_file)
        
        # Step 3: Anti-forensic merge.
        merged_key = AntiForensicMerger.merge(data, self.header_info['af_stripes'])
        self.hex_dump(merged_key)
        return True
        # # Step 4: Unseal TPM key.
        # tpm_unsealer = TPMUnsealer(self.tpm_device)
        # self.tpm_key = tpm_unsealer.unseal()
        
        # # Step 5: Derive decryption key using PBKDF2.
        # derived_key = hashlib.pbkdf2_hmac(
        #     'sha512',
        #     self.tpm_key,
        #     self.header_info['pbkdf_salt'],
        #     100000,  # iteration count
        #     32       # AES-256 key length in bytes
        # )
        
        # # Step 6: Decrypt the merged key using AES ECB mode.
        # cipher = AES.new(derived_key, AES.MODE_ECB)
        # self.volume_key = cipher.decrypt(merged_key)
        
        # # Cleanup temporary keyslot file.
        # keyslot_path = Path(self.keyslot_file)
        # if keyslot_path.exists():
        #     keyslot_path.unlink()
        
        # return self.volume_key

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <block_device>")
        sys.exit(1)
    
    device_path = sys.argv[1]
    extractor = LUKSVolumeKeyExtractor(device_path)
    extractor.run()
    # print("Recovered LUKS volume key:", binascii.hexlify(vol_key).decode())

if __name__ == '__main__':
    main()
