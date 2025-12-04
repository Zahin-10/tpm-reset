#!/home/tahmid/miniconda3/bin/python
import sys
import hashlib
from tpm2_pytss import ESAPI, ESYS_TR, TPM2B_NONCE, TPMT_SYM_DEF, TPML_PCR_SELECTION, TPM2B_DIGEST
from tpm2_pytss.constants import TPM2_ALG, TPM2_SE, TPM2_CAP, TPM2_HT
from tpm2_pytss.types import TPM2B_PUBLIC,TPM2B_PRIVATE
from random import randbytes
import os

def read_file_bytes(path):
    with open(path, mode='rb') as file: # b is important -> binary
        fileContent = file.read()
    return fileContent

def write_file_bytes(path, data):
    with open(path, mode='wb') as file:  # wb is important -> binary write
        file.write(data)
    print(f"Data successfully written to {path}")

def getCapability(ctx):
    more_loaded, loaded_sessions = ctx.get_capability(TPM2_CAP.HANDLES, TPM2_HT.LOADED_SESSION, 100)
    print("Loaded session handles:", loaded_sessions.marshal().hex())

    # Query for saved session handles: sessions that have been context-saved
    more_saved, saved_sessions = ctx.get_capability(TPM2_CAP.HANDLES, TPM2_HT.SAVED_SESSION, 100)
    print("Saved session handles:", saved_sessions.marshal().hex())


def load_tpm_object(ctx, public_data, private_data, parent_handle_value):
    """
    Loads the TPM object into the TPM and returns the handle.

    Args:
        ctx (ESAPI): The TPM2 ESAPI context.
        public_data (path): The TPM2B_PUBLIC data.
        private_data (path): The TPM2B_PRIVATE data.
        parent_handle_value (int): The parent handle value (e.g., 0x81000001).

    Returns:
        ESYS_TR: The transient handle of the loaded object.
    """
    try:
        TPM_PUB, _ = TPM2B_PUBLIC.unmarshal(read_file_bytes(public_data))
        TPM_PRI, _ = TPM2B_PRIVATE.unmarshal(read_file_bytes(private_data))
        parent_handle = ctx.tr_from_tpmpublic(parent_handle_value)
        loaded_handle = ctx.load(parent_handle,in_private = TPM_PRI, in_public= TPM_PUB)
        print("Successfully loaded object")
        return loaded_handle
    except Exception as e:
        print("Failed loading tpm object:", e)
        sys.exit(1)

def select_pcrs():
    try:
        pcr_selection = TPML_PCR_SELECTION.parse("sha256:7,11")
        return pcr_selection
    except Exception as e:
        print("Error parsing PCR selection:", e)
        #ctx.flush_context(session_handle)
        sys.exit(1)
def policy_pcr(ctx, session_handle):
    try:
        pcr_selection = select_pcrs()
        # Read the current PCR values from the TPM.
        # This call returns update_counter, output PCR selection, and the list of PCR digests.
        update_counter, out_selection, pcr_values = ctx.pcr_read(pcr_selection)

        # Concatenate the PCR values.
        # Assuming each digest in pcr_values.digests has a 'buffer' attribute (bytes).
        concatenated_pcrs = b"".join([d.buffer for d in pcr_values.digests])

        # Compute the SHA256 digest of the concatenated PCR values.
        pcr_digest = hashlib.sha256(concatenated_pcrs).digest()

        # Expected digest (as provided) in hex form.
        #expected_digest_hex = "d512efdead12ee76345eb06931863b8940eb9544cc131f3be1c3638f6d961c65"

        # Compare the computed digest with the expected digest.
        #if pcr_digest.hex() != expected_digest_hex:
        #    raise Exception("Computed PCR digest ({}) does not match expected digest ({})"
         #                   .format(pcr_digest.hex(), expected_digest_hex))
        ctx.policy_pcr(
            policy_session=session_handle,
            pcr_digest=pcr_digest,
            pcrs=pcr_selection
        )
        print("PCR policy applied successfully using the manually verified PCR digest.")
    except Exception as e:
        print("Error applying PCR policy:", e)
        ctx.flush_context(session_handle)
        sys.exit(1)
def policy_auth_value(ctx, session_handle):
    try:
        ctx.policy_auth_value(session_handle)
        print("PolicyAuthValue command executed successfully.")
    except Exception as e:
        print("Error executing PolicyAuthValue command:", e)
        ctx.flush_context(session_handle)
        sys.exit(1)

def start_auth_session(ctx):
    # try:
        sym = b'\x00\x10'
        #sym_def, _ = TPMT_SYM_DEF.unmarshal(sym)
        tpm_key = ESYS_TR.NONE  # or a handle to a loaded decrypt key
        bind = ESYS_TR.NONE
        session_type = TPM2_SE.POLICY
        symmetric = TPMT_SYM_DEF.parse("null")
        auth_hash = TPM2_ALG.SHA256
        nonce_caller = None

        session_handle = ctx.start_auth_session(
            tpm_key=tpm_key,  # Use RH_NULL
            bind=bind,     # Use RH_NULL
            session_type=session_type,
            symmetric=symmetric,
            auth_hash=auth_hash,
            nonce_caller=nonce_caller
        )
        print("Policy session started. Handle =", session_handle.serialize(ctx).hex())
        return session_handle
    # except Exception as e:
    #     print("Error starting policy session:", e)
    #     sys.exit(1)

def main():
    try:
        # Initialize the TPM ESAPI context with TCTI for swtpm on TCP port 2321.
        ctx = ESAPI(tcti="swtpm:host=localhost,port=2321")
        print("TPM context initialized using TCTI swtpm:host=localhost,port=2321.")
    except Exception as e:
        print("Error initializing TPM context:", e)
        sys.exit(1)

    # Step 0: Load TPM Object
    loaded_object_handle = load_tpm_object(ctx,"TpmEventLog/output/metadata/linux/TPM2B_PUBLIC.bin","TpmEventLog/output/metadata/linux/TPM2B_PRIVATE.bin",0x81000001)
    # Step 1: Start a policy session.
    session_handle = start_auth_session(ctx)
    # Step 2: Execute the PolicyAuthValue command using the pytss API.
    # policy_auth_value(ctx,session_handle)
    # Step 3: Apply the PCR policy using the byte stream.
    policy_pcr(ctx,session_handle)
    
    # Step 6: Unseal data from persistent object 0x81000001.
    try:
        unsealed_data = ctx.unseal(
            item_handle=loaded_object_handle,
            session1=session_handle
        )
        print("Unsealed data (hex):", unsealed_data.__str__())
        
        # Extract the binary data from the TPM2B_SENSITIVE_DATA object
        # TPM2B structures typically have their data in a 'buffer' attribute
        if hasattr(unsealed_data, 'buffer'):
            binary_data = unsealed_data.buffer
        else:
            # If buffer is not available directly, try to marshal the data
            binary_data = unsealed_data.marshal()
        
        # Extract the last 32 bytes (equivalent to `tail -c 64 | xxd -r -p`)
        # 32 bytes = 64 hex characters
        vmk_data = binary_data[-32:]
        print(f"Extracted last 32 bytes from {len(binary_data)} bytes of unsealed data")
        
        # Save the VMK data to a file
        write_file_bytes("unsealed-blob.bin", vmk_data)
        print("Volume Master Key (VMK) / LUKS Unsealed Keyslot successfully saved to unsealed-blob.bin")
    except Exception as e:
        print("Error during unseal operation:", e)
    finally:
        try:
            ctx.flush_context(session_handle)
            print("Policy session flushed successfully.")
        except Exception as flush_e:
            print("Error flushing session:", flush_e)

if __name__ == '__main__':
    main()
