"""Generate a small 20-window PCAP for the offline demo.

The command writes to a caller-provided path so existing backend/samples files are
never changed implicitly:

    python scripts/generate_sample_pcap.py --output demo_scan.pcap
"""
from __future__ import annotations

import argparse
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter


def write_sample(path: Path) -> None:
    writer = PcapWriter(str(path), sync=True)
    base = 1_700_000_000.0
    for window in range(20):
        timestamp = base + window * 60
        for host, port_base in (("10.0.0.1", 80), ("10.0.0.9", 4000)):
            for offset in range(3):
                packet = Ether() / IP(src=host, dst="10.0.1.1", ttl=64) / TCP(
                    sport=port_base + offset,
                    dport=80 if host == "10.0.0.1" else 4000 + window * 3 + offset,
                    flags="S",
                    seq=window * 100 + offset,
                    window=4096,
                )
                packet.time = timestamp + offset * 0.01
                writer.write(packet)
    writer.close()


def write_recon_exfil_sample(path: Path) -> None:
    writer = PcapWriter(str(path), sync=True)
    base = 1_700_100_000.0
    common_ports = (80, 443, 53, 22)
    benign_hosts = [f"10.1.0.{index}" for index in range(1, 7)]
    for window in range(20):
        timestamp = base + window * 60
        for host_index, host in enumerate(benign_hosts):
            for offset, port in enumerate(common_ports):
                packet = Ether() / IP(src=host, dst=f"10.1.1.{host_index + 1}", ttl=64) / TCP(
                    sport=10000 + window * 10 + offset,
                    dport=port,
                    flags="S",
                    seq=window * 100 + offset,
                    window=4096,
                )
                packet.time = timestamp + host_index * 0.001 + offset * 0.01
                writer.write(packet)
        if 5 <= window <= 9:
            for target_index in range(5):
                for port_offset in range(100):
                    packet = Ether() / IP(src="10.1.0.50", dst=f"10.1.2.{target_index + 1}", ttl=48) / TCP(
                        sport=20000 + window,
                        dport=1000 + port_offset,
                        flags="S",
                        seq=port_offset,
                        window=1024,
                    )
                    packet.time = timestamp + 0.2 + target_index * 0.001 + port_offset * 0.0001
                    writer.write(packet)
        if 8 <= window <= 14:
            for offset in range(3):
                packet = Ether() / IP(src="10.1.0.60", dst="198.51.100.60", ttl=52) / UDP(
                    sport=30000 + window * 3 + offset,
                    dport=443,
                ) / Raw(b"X" * 30_000)
                packet.time = timestamp + 0.4 + offset * 0.1
                writer.write(packet)
    writer.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a small NetFlow-V3-compatible demo PCAP.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", choices=("port-scan", "recon-exfil"), default="port-scan")
    args = parser.parse_args()
    if args.scenario == "recon-exfil":
        write_recon_exfil_sample(args.output)
    else:
        write_sample(args.output)
    print(f"wrote {args.output} ({args.output.stat().st_size} bytes)")
