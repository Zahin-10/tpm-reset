sudo mkdir -p /mnt/bitlocker
sudo mkdir -p /mnt/decrypted
sudo dislocker -v -V /dev/nbd0p3 -K ./VMK.bin -- /mnt/bitlocker
sudo mount -o loop /mnt/bitlocker/dislocker-file /mnt/decrypted
