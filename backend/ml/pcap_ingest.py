"""Streaming PCAP-to-NetFlow-V3 adapter for the host forecast pipeline."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader

from .host_v3 import PASS2_COLS

IDLE_TIMEOUT_S = 120.0
# Exporter timeout docs are unavailable offline; keep the training window at 60 s.
ACTIVE_TIMEOUT_S = 60.0
MAX_ACTIVE_FLOWS = 50_000


@dataclass
class _Flow:
    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: int
    first_ts: float
    last_ts: float
    window_start_ts: float
    in_bytes: int = 0
    out_bytes: int = 0
    in_pkts: int = 0
    out_pkts: int = 0
    tcp_flags: int = 0
    min_ttl: int = 255
    max_ttl: int = 0
    win_in: int = 0
    win_out: int = 0
    retrans_in: int = 0
    retrans_out: int = 0
    seq_in: set[int] = field(default_factory=set)
    seq_out: set[int] = field(default_factory=set)
    iat_in: list[float] = field(default_factory=list)
    iat_out: list[float] = field(default_factory=list)
    last_in: float | None = None
    last_out: float | None = None

    def add(self, packet, timestamp: float, source_direction: bool) -> None:
        payload_bytes = len(bytes(packet.payload)) if packet.payload else 0
        size = len(bytes(packet))
        ttl = int(packet.ttl)
        self.last_ts = timestamp
        self.min_ttl = min(self.min_ttl, ttl)
        self.max_ttl = max(self.max_ttl, ttl)
        # NetFlow-V3 IN/OUT direction is exporter-dependent; this adapter uses
        # the first packet sender as source and maps source-to-destination to OUT.
        if source_direction:
            self.out_bytes += size
            self.out_pkts += 1
            if self.last_out is not None:
                self.iat_out.append(max(0.0, (timestamp - self.last_out) * 1000.0))
            self.last_out = timestamp
            if TCP in packet:
                self.win_out = max(self.win_out, int(packet[TCP].window))
                self.tcp_flags |= int(packet[TCP].flags)
                if payload_bytes:
                    seq = int(packet[TCP].seq)
                    # Retransmission is approximated as a repeated TCP sequence
                    # number with a non-empty payload within this bounded flow.
                    if seq in self.seq_out:
                        self.retrans_out += 1
                    self.seq_out.add(seq)
        else:
            self.in_bytes += size
            self.in_pkts += 1
            if self.last_in is not None:
                self.iat_in.append(max(0.0, (timestamp - self.last_in) * 1000.0))
            self.last_in = timestamp
            if TCP in packet:
                self.win_in = max(self.win_in, int(packet[TCP].window))
                self.tcp_flags |= int(packet[TCP].flags)
                if payload_bytes:
                    seq = int(packet[TCP].seq)
                    # Retransmission is approximated as a repeated TCP sequence
                    # number with a non-empty payload within this bounded flow.
                    if seq in self.seq_in:
                        self.retrans_in += 1
                    self.seq_in.add(seq)

    def row(self) -> dict:
        def stat(values: list[float], kind: str) -> float:
            if not values:
                return 0.0
            if kind == "max":
                return float(max(values))
            if kind == "std":
                return float(np.std(values))
            return float(np.mean(values))

        # NetFlow-V3 stores duration and IAT statistics in milliseconds. PCAP timestamps
        # are seconds, so this adapter converts both quantities to milliseconds here.
        return {
            "FLOW_START_MILLISECONDS": int(round(self.first_ts * 1000.0)),
            "IPV4_SRC_ADDR": self.src,
            "Attack": "Benign",
            "IPV4_DST_ADDR": self.dst,
            "L4_DST_PORT": self.dst_port,
            "PROTOCOL": self.protocol,
            "IN_BYTES": self.in_bytes,
            "IN_PKTS": self.in_pkts,
            "OUT_BYTES": self.out_bytes,
            "OUT_PKTS": self.out_pkts,
            "TCP_FLAGS": self.tcp_flags,
            "FLOW_DURATION_MILLISECONDS": int(round((self.last_ts - self.first_ts) * 1000.0)),
            # NetFlow-V3 has min/max TTL but not a packet-level mean; the host builder
            # computes the same midpoint from these two per-flow extrema.
            "MIN_TTL": self.min_ttl if self.max_ttl else 0,
            "MAX_TTL": self.max_ttl,
            "RETRANSMITTED_IN_PKTS": self.retrans_in,
            "RETRANSMITTED_OUT_PKTS": self.retrans_out,
            "TCP_WIN_MAX_IN": self.win_in,
            "TCP_WIN_MAX_OUT": self.win_out,
            "SRC_TO_DST_IAT_MAX": stat(self.iat_out, "max"),
            "SRC_TO_DST_IAT_AVG": stat(self.iat_out, "mean"),
            "SRC_TO_DST_IAT_STDDEV": stat(self.iat_out, "std"),
            "DST_TO_SRC_IAT_MAX": stat(self.iat_in, "max"),
            "DST_TO_SRC_IAT_AVG": stat(self.iat_in, "mean"),
            "DST_TO_SRC_IAT_STDDEV": stat(self.iat_in, "std"),
        }


def _packet_info(packet) -> tuple[str, str, int, int, int] | None:
    if IP not in packet:
        return None
    ip = packet[IP]
    if TCP in packet:
        transport = packet[TCP]
        return ip.src, ip.dst, int(transport.sport), int(transport.dport), 6
    if UDP in packet:
        transport = packet[UDP]
        return ip.src, ip.dst, int(transport.sport), int(transport.dport), 17
    return ip.src, ip.dst, 0, 0, int(ip.proto)


def _flow_key(src: str, dst: str, src_port: int, dst_port: int, protocol: int) -> tuple:
    left = (src, src_port)
    right = (dst, dst_port)
    endpoints = (left, right) if left <= right else (right, left)
    return protocol, endpoints[0], endpoints[1]


def iter_pcap_rows(path: Path, idle_timeout_s: float = IDLE_TIMEOUT_S) -> tuple[Iterator[dict], dict]:
    """Yield closed flow rows while retaining only active idle-window state."""
    active: dict[tuple, _Flow] = {}
    stats = {"packets": 0, "skipped_packets": 0, "flows": 0}

    def rows() -> Iterator[dict]:
        try:
            with PcapReader(str(path)) as reader:
                for packet in reader:
                    stats["packets"] += 1
                    info = _packet_info(packet)
                    if info is None:
                        stats["skipped_packets"] += 1
                        continue
                    src, dst, src_port, dst_port, protocol = info
                    timestamp = float(packet.time)
                    stale = [key for key, flow in active.items() if timestamp - flow.last_ts > idle_timeout_s]
                    for key in stale:
                        stats["flows"] += 1
                        yield active.pop(key).row()
                    key = _flow_key(src, dst, src_port, dst_port, protocol)
                    flow = active.get(key)
                    window_start = timestamp // ACTIVE_TIMEOUT_S * ACTIVE_TIMEOUT_S
                    if flow is not None and flow.window_start_ts != window_start:
                        stats["flows"] += 1
                        yield active.pop(key).row()
                        flow = None
                    if flow is None:
                        if len(active) >= MAX_ACTIVE_FLOWS:
                            oldest = min(active, key=lambda item: active[item].last_ts)
                            stats["flows"] += 1
                            yield active.pop(oldest).row()
                        flow = _Flow(src, dst, src_port, dst_port, protocol, timestamp, timestamp, window_start)
                        active[key] = flow
                    source_direction = src == flow.src and src_port == flow.src_port and dst == flow.dst and dst_port == flow.dst_port
                    flow.add(packet, timestamp, source_direction)
            for flow in active.values():
                stats["flows"] += 1
                yield flow.row()
        finally:
            active.clear()

    return rows(), stats


def pcap_to_frame(path: Path, idle_timeout_s: float = IDLE_TIMEOUT_S) -> tuple[pd.DataFrame, dict]:
    rows, stats = iter_pcap_rows(path, idle_timeout_s=idle_timeout_s)
    frame = pd.DataFrame(rows, columns=PASS2_COLS)
    if len(frame):
        frame = frame.sort_values("FLOW_START_MILLISECONDS").reset_index(drop=True)
    frame.attrs["pcap_stats"] = stats
    return frame, stats
