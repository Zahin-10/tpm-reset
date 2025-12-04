from tpm2_pytss import TPM2_SU,ESAPI, ESYS_TR, TPM2B_NONCE, TPMT_SYM_DEF, TPML_PCR_SELECTION, TPM2B_DIGEST
from tpm2_pytss.constants import TPM2_ALG, TPM2_SE, TPM2_CAP, TPM2_HT
from os import sys
def read_pcr7_sha256(ctx):
    """Read PCR7 value for SHA-256 bank with proper selection"""
    try:
        pcr_update_counter, pcr_selection_out, pcr_values = ctx.pcr_read("sha256:7")
    
        # Extract SHA-256 digest from first digest entry
        print(f"PCR7 (SHA-256): {pcr_values.digests[0].buffer.hex()}")
    except Exception as e:
        print(f"PCR read failed: {e}")

try:
    # Initialize the TPM ESAPI context with TCTI for swtpm on TCP port 2321.
    ctx = ESAPI(tcti="swtpm:host=localhost,port=2321")
    print("TPM context initialized using TCTI swtpm:host=localhost,port=2321.")
    read_pcr7_sha256(ctx)
    ctx.shutdown(TPM2_SU.CLEAR)
    ctx.startup(TPM2_SU.CLEAR)
    read_pcr7_sha256(ctx)
except Exception as e:
    print("Error initializing TPM context:", e)
    sys.exit(1)
