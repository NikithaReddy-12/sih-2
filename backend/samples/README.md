# Forecast samples

These NetFlow-V3 slices were chosen by label from the test split only.
Model output was not used to pick the windows.

Each attack slice keeps at least 10 context windows before the labeled window and 5 after it.
The benign slice is 16 test windows that contain no attack label.
Every flow in those windows is kept, for every host.

`kill_chain_replay.csv.gz` stitches the real test slices for brute force, infiltration, and bot
by shifting FLOW_START_MILLISECONDS so the slices follow each other.
composed replay of real test windows from three different captures, not a single real attack.

`port_scan_demo.pcap` and `port_scan_demo.pcapng` are synthetic captures generated
from `scripts/generate_sample_pcap.py`-compatible Scapy packets. They span 20
synthetic one-minute windows, include benign traffic from `10.0.0.1`, and include
a distinct-destination-port scanning host at `10.0.0.9`. They are for offline
demonstration only and have no ground-truth entry.

`recon_exfil_demo.pcap` is synthetic and generated with
`scripts/generate_sample_pcap.py --scenario recon-exfil`. It contains six
benign hosts over 20 windows, a 100-port scanner across five windows, and a
large-transfer host across seven windows. Its recon and exfil labels are
heuristic-only and are not learned-model ground truth.
