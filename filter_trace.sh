# Find first Unseal command
unseal_frame=$(tshark -r data/windows/secboot.pcapng -Y 'frame[72:4] == 00:00:01:5e' -T fields -e frame.number | head -1)

# Capture frames until first Unseal command
tshark -r data/windows/secboot.pcapng -Y "(frame[72:4] == 00:00:01:82) && (frame.number <= ${unseal_frame})" -T fields -E header=n -E separator=, -E quote=d -e tcp.payload > data/windows/input.csv
