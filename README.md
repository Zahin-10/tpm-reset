# PCR7 Measured Boot Digest Calculator

This tool calculates the expected PCR7 digest value for UEFI Secure Boot "db" variable.

## Background

In UEFI Secure Boot, PCR7 contains measurements of the Secure Boot policy, including the certificates used to verify boot components. This script simulates how UEFI measures the "db" variable into PCR7.

## Key Discovery

The script implements the exact approach used by UEFI firmware to measure the "db" variable into PCR7:

1. It uses just the EFI_SIGNATURE_DATA portion (owner GUID + certificate) rather than the entire EFI_SIGNATURE_LIST.
2. It creates the UEFI_VARIABLE_DATA structure exactly as done in the UEFI code.
3. It uses the OVMF GUID by default (d719b2cb-3d3a-4596-a3bc-dad00e67656f) or a custom GUID if provided.

## Usage

```bash
python pcr7_measured_boot_digest.py --cert <certificate-file> [options]
```

### Options

- `--cert`: Required. Path to the certificate file in DER format
- `--guid`: Custom GUID to use (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx). If not provided, uses OVMF GUID
- `--expected`: Expected digest value to compare with
- `--save`: Save the UEFI_VARIABLE_DATA structure to a file
- `--verbose`: Show verbose output

### Examples

Calculate digest using OVMF GUID (default):

```bash
python pcr7_measured_boot_digest.py --cert data/MicWinProPCA2011_2011-10-19.crt
```

Calculate digest with a custom GUID:

```bash
python pcr7_measured_boot_digest.py --cert data/MicWinProPCA2011_2011-10-19.crt --guid d719b2cb-3d3a-4596-a3bc-dad00e67656f
```

Compare with expected digest:

```bash
python pcr7_measured_boot_digest.py --cert data/MicWinProPCA2011_2011-10-19.crt --expected 51E06158660B95D3C9A4EBE6FE6B825C4586903EBFC6EE9950694A8B64DEA78F
```

Save the UEFI_VARIABLE_DATA structure:

```bash
python pcr7_measured_boot_digest.py --cert data/MicWinProPCA2011_2011-10-19.crt --save db_measurement.bin
```

## Implementation Notes

The script implements the measurement process as defined in the UEFI code:

```c
EFI_STATUS MeasureVariable(
  IN      CHAR16    *VarName,  // Always "db"
  IN      EFI_GUID  *VendorGuid,
  IN      VOID      *VarData,
  IN      UINTN     VarSize
)
```

Where the comment in the UEFI code states:
> "The UEFI_VARIABLE_DATA.VariableData value shall be the EFI_SIGNATURE_DATA value from the EFI_SIGNATURE_LIST that contained the authority that was used to validate the image"

This explains why:
1. We need just the SignatureData (not the entire SignatureList)
2. It's just one certificate (the one used to validate the image)
3. The memory layout must precisely match what UEFI does internally

## Verified Result

Using the Microsoft Windows Production PCA 2011 certificate with the OVMF GUID, the calculated digest matches the expected PCR7 value from the system:

```
51e06158660b95d3c9a4ebe6fe6b825c4586903ebfc6ee9950694a8b64dea78f
```

This confirms that the TPM is correctly measuring the certificates used for Secure Boot. 