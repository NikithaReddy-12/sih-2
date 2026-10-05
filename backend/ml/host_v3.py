"""Per-host windows for the NetFlow-V3 capture.

Each row is one source IPv4 in one 60-second window. The host address is kept
only as an identifier for sequences. It is not a model feature. The network-level
pipeline in netflow_v3.py is unchanged.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from .config import ACK, FIN, GAP_MS, PSH, RST, SYN, URG
from .netflow_v3 import (
    CACHE_DIR,
    MAPPED_STAGES,
    _ipv4_to_uint32,
    _num,
    attack_bucket,
    load_windows,
    modeling_frame,
)

HOST_CACHE_VERSION = 1
MIN_FLOWS = 3
TOP_HOSTS = 500
LABEL_FRAC = 0.5

FLOW_FEATURES = [
    "log1p_n_flows",
    "log1p_uniq_dst_ips",
    "log1p_uniq_dst_ports",
    "syn_ratio",
    "rst_ratio",
    "ack_ratio",
    "fin_ratio",
    "psh_ratio",
    "urg_ratio",
    "no_response_share",
    "small_flow_share",
    "mean_log_in_bytes",
    "mean_log_out_bytes",
    "log1p_out_in_byte_ratio",
    "mean_log_duration",
]
PACKET_FEATURES = [
    "log1p_port_scan_score",
    "mean_ttl",
    "log1p_ttl_var",
    "log1p_mean_tcp_win_in",
    "log1p_mean_tcp_win_out",
    "retrans_ratio",
    "log1p_iat_mean",
    "log1p_iat_max",
    "log1p_iat_std",
]
CONCENTRATION_FEATURES = [
    "top_dst_port_share",
    "top_dst_ip_share",
]
CONTEXT_FEATURES = [
    "log1p_window_flows",
    "active_hosts",
    "active",
]
HOST_FEATURES = FLOW_FEATURES + PACKET_FEATURES + CONCENTRATION_FEATURES + CONTEXT_FEATURES
HEAVY_FEATURES = [
    name for name in HOST_FEATURES
    if name.startswith("log1p_") or name.startswith("mean_log")
]

COUNT_COLS = ["n", "n_benign", "n_initial", "n_lateral", "n_c2", "n_excluded", "n_other"]
PASS1_COLS = ["FLOW_START_MILLISECONDS", "IPV4_SRC_ADDR", "Attack"]
PASS2_COLS = PASS1_COLS + [
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "MIN_TTL",
    "MAX_TTL",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_PKTS",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG",
    "DST_TO_SRC_IAT_STDDEV",
]


def _cache_paths(window_s: int) -> tuple[Path, Path]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"host_v3_w{int(window_s)}_v{HOST_CACHE_VERSION}"
    return CACHE_DIR / f"{stem}.csv.gz", CACHE_DIR / f"{stem}.meta.json"


def select_hosts(counts: pd.DataFrame, min_flows: int = MIN_FLOWS, top: int = TOP_HOSTS) -> pd.DataFrame:
    """Keep hosts with enough flows, then the busiest hosts in each window.

    The sort key is the flow count. The source id breaks ties. Labels are not used.
    """
    kept = counts.loc[counts["n"] >= int(min_flows)].copy()
    kept = kept.sort_values(["window", "n", "src"], ascending=[True, False, True])
    kept["rank"] = kept.groupby("window", sort=False).cumcount()
    return kept.loc[kept["rank"] < int(top)].drop(columns="rank")


def retained_flow_shares(counts: pd.DataFrame, selected: pd.DataFrame) -> dict:
    shares = {}
    for column, name in (
        ("n_initial", "initial_access"),
        ("n_lateral", "lateral_movement"),
        ("n_c2", "command_and_control"),
        ("n_excluded", "dos_ddos_web"),
        ("n_other", "other"),
        ("n_benign", "benign"),
    ):
        total = float(counts[column].sum())
        kept = float(selected[column].sum()) if len(selected) else 0.0
        shares[name] = None if total == 0 else kept / total
    return shares


def label_host_rows(frame: pd.DataFrame, min_frac: float = LABEL_FRAC) -> pd.DataFrame:
    """Stage if that attack is at least half the host's flows. Drop DoS/DDoS/Web above half."""
    out = frame.copy()
    for column in ("n", "n_initial", "n_lateral", "n_c2", "n_excluded"):
        out[column] = out[column].fillna(0)
    total = np.maximum(out["n"].to_numpy(np.float64), 1.0)
    excluded = out["n_excluded"].to_numpy(np.float64) / total
    mapped = out[["n_initial", "n_lateral", "n_c2"]].to_numpy(np.float64) / total[:, None]
    top = mapped.argmax(axis=1)
    top_share = mapped.max(axis=1)
    names = np.asarray(MAPPED_STAGES, dtype=object)
    stage = np.where(top_share >= float(min_frac), names[top], "benign")
    stage = np.where(excluded > float(min_frac), "dropped", stage)
    out["stage"] = stage
    return out


def _pack(window: np.ndarray, src: np.ndarray) -> np.ndarray:
    return (window.astype(np.uint64) << np.uint64(32)) | src.astype(np.uint64)


def _selected_mask(window: np.ndarray, src: np.ndarray, chosen: np.ndarray) -> np.ndarray:
    if len(chosen) == 0 or len(window) == 0:
        return np.zeros(len(window), dtype=bool)
    packed = _pack(window, src)
    index = np.searchsorted(chosen, packed)
    index = np.clip(index, 0, len(chosen) - 1)
    return packed == chosen[index]


def _sum_counts(parts: list[pd.DataFrame]) -> pd.DataFrame:
    if not parts:
        return pd.DataFrame(columns=["window", "src", *COUNT_COLS])
    stacked = pd.concat(parts)
    if isinstance(stacked.index, pd.MultiIndex):
        stacked = stacked.groupby(level=[0, 1], sort=False).sum()
    return stacked.reset_index()


def _pass1(csv_path: Path, window_ms: int) -> tuple[pd.DataFrame, dict]:
    parts = []
    class_flows = {name: 0 for name in ("benign", "initial_access", "lateral_movement", "command_and_control", "excluded", "other")}
    rows = 0
    min_ms = None
    max_ms = None
    for index, chunk in enumerate(pd.read_csv(csv_path, usecols=PASS1_COLS, chunksize=1_000_000)):
        ts = _num(chunk["FLOW_START_MILLISECONDS"]).astype(np.int64)
        if len(ts):
            lo = int(ts.min())
            hi = int(ts.max())
            min_ms = lo if min_ms is None else min(min_ms, lo)
            max_ms = hi if max_ms is None else max(max_ms, hi)
        buckets = chunk["Attack"].map(attack_bucket)
        for name in class_flows:
            class_flows[name] += int((buckets == name).sum())
        work = pd.DataFrame({
            "window": (ts // window_ms).astype(np.int64),
            "src": _ipv4_to_uint32(chunk["IPV4_SRC_ADDR"]),
            "n": np.int32(1),
            "n_benign": (buckets == "benign").to_numpy(np.int32),
            "n_initial": (buckets == "initial_access").to_numpy(np.int32),
            "n_lateral": (buckets == "lateral_movement").to_numpy(np.int32),
            "n_c2": (buckets == "command_and_control").to_numpy(np.int32),
            "n_excluded": (buckets == "excluded").to_numpy(np.int32),
            "n_other": (buckets == "other").to_numpy(np.int32),
        })
        parts.append(work.groupby(["window", "src"], sort=False)[COUNT_COLS].sum())
        if len(parts) >= 4:
            parts = [_sum_counts(parts).set_index(["window", "src"])]
        rows += len(chunk)
        print(f"host pass1 chunk {index} rows {len(chunk)} total_rows {rows}", flush=True)
        del chunk, work
    counts = _sum_counts(parts)
    meta = {"rows": rows, "min_ms": min_ms, "max_ms": max_ms, "class_flows": class_flows}
    return counts, meta


def _numeric_frame(frame: pd.DataFrame) -> pd.DataFrame:
    protocol = _num(frame["PROTOCOL"]).astype(np.int64)
    flags = _num(frame["TCP_FLAGS"]).astype(np.int64)
    tcp = protocol == 6
    in_pkts = np.clip(_num(frame["IN_PKTS"]), 0, None)
    out_pkts = np.clip(_num(frame["OUT_PKTS"]), 0, None)
    in_bytes = np.clip(_num(frame["IN_BYTES"]), 0, None)
    out_bytes = np.clip(_num(frame["OUT_BYTES"]), 0, None)
    duration = np.clip(_num(frame["FLOW_DURATION_MILLISECONDS"]), 0, None)
    min_ttl = _num(frame["MIN_TTL"])
    max_ttl = _num(frame["MAX_TTL"])
    ttl = (min_ttl + max_ttl) / 2.0
    retrans = np.clip(_num(frame["RETRANSMITTED_IN_PKTS"]), 0, None) + np.clip(_num(frame["RETRANSMITTED_OUT_PKTS"]), 0, None)
    iat_mean = (np.clip(_num(frame["SRC_TO_DST_IAT_AVG"]), 0, None) + np.clip(_num(frame["DST_TO_SRC_IAT_AVG"]), 0, None)) / 2.0
    iat_max = np.maximum(np.clip(_num(frame["SRC_TO_DST_IAT_MAX"]), 0, None), np.clip(_num(frame["DST_TO_SRC_IAT_MAX"]), 0, None))
    iat_std = (np.clip(_num(frame["SRC_TO_DST_IAT_STDDEV"]), 0, None) + np.clip(_num(frame["DST_TO_SRC_IAT_STDDEV"]), 0, None)) / 2.0
    return pd.DataFrame({
        "window": frame["window"].to_numpy(np.int64),
        "src": frame["src"].to_numpy(np.uint32),
        "n": np.int32(1),
        "tcp_n": tcp.astype(np.int32),
        "syn_n": (tcp & ((flags & SYN) != 0)).astype(np.int32),
        "rst_n": (tcp & ((flags & RST) != 0)).astype(np.int32),
        "ack_n": (tcp & ((flags & ACK) != 0)).astype(np.int32),
        "fin_n": (tcp & ((flags & FIN) != 0)).astype(np.int32),
        "psh_n": (tcp & ((flags & PSH) != 0)).astype(np.int32),
        "urg_n": (tcp & ((flags & URG) != 0)).astype(np.int32),
        "no_response_n": (tcp & (out_pkts == 0)).astype(np.int32),
        "small_n": ((in_pkts + out_pkts) <= 3).astype(np.int32),
        "sum_log_in_bytes": np.log1p(in_bytes),
        "sum_log_out_bytes": np.log1p(out_bytes),
        "in_bytes": in_bytes,
        "out_bytes": out_bytes,
        "in_pkts": in_pkts,
        "out_pkts": out_pkts,
        "sum_log_duration": np.log1p(duration),
        "sum_ttl": ttl,
        "sumsq_ttl": ttl * ttl,
        "sum_win_in": np.clip(_num(frame["TCP_WIN_MAX_IN"]), 0, None),
        "sum_win_out": np.clip(_num(frame["TCP_WIN_MAX_OUT"]), 0, None),
        "retrans_pkts": retrans,
        "sum_iat_mean": iat_mean,
        "sum_iat_max": iat_max,
        "sum_iat_std": iat_std,
    })


def _pass2(csv_path: Path, window_ms: int, chosen: np.ndarray, keep_flows: bool = False):
    numeric_parts = []
    quad_parts = []
    flow_parts = []
    port_counts: dict[int, int] = {}
    for index, chunk in enumerate(pd.read_csv(csv_path, usecols=PASS2_COLS, chunksize=1_000_000)):
        ts = _num(chunk["FLOW_START_MILLISECONDS"]).astype(np.int64)
        window = (ts // window_ms).astype(np.int64)
        src = _ipv4_to_uint32(chunk["IPV4_SRC_ADDR"])
        if keep_flows:
            ports = np.clip(_num(chunk["L4_DST_PORT"]), 0, 65535).astype(np.int64)
            uniq, counts = np.unique(ports, return_counts=True)
            for port, count in zip(uniq, counts):
                port_counts[int(port)] = port_counts.get(int(port), 0) + int(count)
        mask = _selected_mask(window, src, chosen)
        kept = int(mask.sum())
        print(f"host pass2 chunk {index} kept {kept}", flush=True)
        if kept == 0:
            del chunk
            continue
        sub = chunk.loc[mask].copy()
        sub["window"] = window[mask]
        sub["src"] = src[mask]
        numbers = _numeric_frame(sub)
        numeric_parts.append(numbers.groupby(["window", "src"], sort=False).sum())
        quad_parts.append(pd.DataFrame({
            "window": sub["window"].to_numpy(np.uint32),
            "src": sub["src"].to_numpy(np.uint32),
            "dst": _ipv4_to_uint32(sub["IPV4_DST_ADDR"]),
            "dport": np.clip(_num(sub["L4_DST_PORT"]), 0, 65535).astype(np.uint32),
        }).groupby(["window", "src", "dst", "dport"], sort=False).size().rename("quad_n").reset_index())
        if keep_flows:
            flow_parts.append(pd.DataFrame({
                "window": sub["window"].to_numpy(np.int64),
                "src": sub["src"].to_numpy(np.uint32),
                "dst_ip": sub["IPV4_DST_ADDR"].astype(str).to_numpy(),
                "dst_port": np.clip(_num(sub["L4_DST_PORT"]), 0, 65535).astype(np.int64),
                "protocol": _num(sub["PROTOCOL"]).astype(np.int64),
                "bytes": np.clip(_num(sub["IN_BYTES"]), 0, None) + np.clip(_num(sub["OUT_BYTES"]), 0, None),
                "tcp_flags": _num(sub["TCP_FLAGS"]).astype(np.int64),
            }))
        if len(numeric_parts) >= 4:
            numeric_parts = [pd.concat(numeric_parts).groupby(level=[0, 1], sort=False).sum()]
        if len(quad_parts) >= 4:
            quad_parts = [_merge_quads(quad_parts)]
        if keep_flows and len(flow_parts) >= 4:
            flow_parts = [pd.concat(flow_parts, ignore_index=True)]
        del chunk, sub, numbers
    numeric = pd.concat(numeric_parts).groupby(level=[0, 1], sort=False).sum().reset_index() if numeric_parts else pd.DataFrame()
    quads = _merge_quads(quad_parts) if quad_parts else pd.DataFrame(columns=["window", "src", "dst", "dport", "quad_n"])
    flows = pd.concat(flow_parts, ignore_index=True) if flow_parts else pd.DataFrame(
        columns=["window", "src", "dst_ip", "dst_port", "protocol", "bytes", "tcp_flags"]
    )
    return numeric, quads, flows, port_counts


def _merge_quads(parts: list[pd.DataFrame]) -> pd.DataFrame:
    stacked = pd.concat(parts, ignore_index=True)
    return stacked.groupby(["window", "src", "dst", "dport"], sort=False)["quad_n"].sum().reset_index()


def _diversity(quads: pd.DataFrame) -> pd.DataFrame:
    if len(quads) == 0:
        return pd.DataFrame(columns=["window", "src", "uniq_dst", "uniq_dport", "port_scan", "top_dst_ip", "top_dst_port"])
    uniq_dst = quads.groupby(["window", "src"], sort=False)["dst"].nunique().rename("uniq_dst")
    uniq_port = quads.groupby(["window", "src"], sort=False)["dport"].nunique().rename("uniq_dport")
    scan = quads.groupby(["window", "src", "dst"], sort=False)["dport"].nunique().groupby(["window", "src"], sort=False).max().rename("port_scan")
    dst_counts = quads.groupby(["window", "src", "dst"], sort=False)["quad_n"].sum().groupby(["window", "src"], sort=False).max().rename("top_dst_ip")
    port_counts = quads.groupby(["window", "src", "dport"], sort=False)["quad_n"].sum().groupby(["window", "src"], sort=False).max().rename("top_dst_port")
    return uniq_dst.to_frame().join(uniq_port, how="outer").join(scan, how="outer").join(dst_counts, how="outer").join(port_counts, how="outer").reset_index()


def build_host_features(frame: pd.DataFrame) -> pd.DataFrame:
    total = np.maximum(frame["n"].to_numpy(np.float64), 1.0)
    tcp = frame["tcp_n"].to_numpy(np.float64)
    in_bytes = frame["in_bytes"].to_numpy(np.float64)
    out_bytes = frame["out_bytes"].to_numpy(np.float64)
    ratio = np.divide(out_bytes, in_bytes, out=np.zeros_like(out_bytes), where=in_bytes > 0)
    ratio = np.where((in_bytes <= 0) & (out_bytes > 0), out_bytes, ratio)
    pkts = frame["in_pkts"].to_numpy(np.float64) + frame["out_pkts"].to_numpy(np.float64)
    retrans = np.minimum(np.divide(frame["retrans_pkts"].to_numpy(np.float64), pkts, out=np.zeros_like(pkts), where=pkts > 0), 1.0)
    mean_ttl = frame["sum_ttl"].to_numpy(np.float64) / total
    variance = np.maximum(frame["sumsq_ttl"].to_numpy(np.float64) / total - mean_ttl ** 2, 0.0)

    def flag(column: str) -> np.ndarray:
        counts = frame[column].to_numpy(np.float64)
        return np.divide(counts, tcp, out=np.zeros_like(counts), where=tcp > 0)

    data = {
        "log1p_n_flows": np.log1p(frame["n"].to_numpy(np.float64)),
        "log1p_uniq_dst_ips": np.log1p(frame["uniq_dst"].to_numpy(np.float64)),
        "log1p_uniq_dst_ports": np.log1p(frame["uniq_dport"].to_numpy(np.float64)),
        "syn_ratio": flag("syn_n"),
        "rst_ratio": flag("rst_n"),
        "ack_ratio": flag("ack_n"),
        "fin_ratio": flag("fin_n"),
        "psh_ratio": flag("psh_n"),
        "urg_ratio": flag("urg_n"),
        "no_response_share": flag("no_response_n"),
        "small_flow_share": frame["small_n"].to_numpy(np.float64) / total,
        "mean_log_in_bytes": frame["sum_log_in_bytes"].to_numpy(np.float64) / total,
        "mean_log_out_bytes": frame["sum_log_out_bytes"].to_numpy(np.float64) / total,
        "log1p_out_in_byte_ratio": np.log1p(np.clip(ratio, 0, None)),
        "mean_log_duration": frame["sum_log_duration"].to_numpy(np.float64) / total,
        "log1p_port_scan_score": np.log1p(frame["port_scan"].to_numpy(np.float64)),
        "mean_ttl": mean_ttl,
        "log1p_ttl_var": np.log1p(variance),
        "log1p_mean_tcp_win_in": np.log1p(frame["sum_win_in"].to_numpy(np.float64) / total),
        "log1p_mean_tcp_win_out": np.log1p(frame["sum_win_out"].to_numpy(np.float64) / total),
        "retrans_ratio": retrans,
        "log1p_iat_mean": np.log1p(frame["sum_iat_mean"].to_numpy(np.float64) / total),
        "log1p_iat_max": np.log1p(frame["sum_iat_max"].to_numpy(np.float64) / total),
        "log1p_iat_std": np.log1p(frame["sum_iat_std"].to_numpy(np.float64) / total),
        "top_dst_port_share": frame["top_dst_port"].to_numpy(np.float64) / total,
        "top_dst_ip_share": frame["top_dst_ip"].to_numpy(np.float64) / total,
        "log1p_window_flows": np.log1p(frame["window_flows"].to_numpy(np.float64)),
        "active_hosts": frame["active_hosts"].to_numpy(np.float64),
        "active": np.ones(len(frame), dtype=np.float64),
    }
    return pd.DataFrame({name: data[name] for name in HOST_FEATURES})


def _print_shares(shares: dict) -> None:
    print("attack_flow_share_retained", flush=True)
    for name, share in shares.items():
        if share is None:
            print(f"  {name} no flows", flush=True)
            continue
        print(f"  {name} {share:.4f}", flush=True)
        if name in {"initial_access", "lateral_movement", "command_and_control", "dos_ddos_web"} and share < 0.80:
            print(
                f"WARNING: only {share:.1%} of {name} flows were retained after the "
                f">={MIN_FLOWS}-flow and top-{TOP_HOSTS} host filter. That is below 80%.",
                flush=True,
            )


def ipv4_from_uint32(value: int) -> str:
    packed = int(value) & 0xFFFFFFFF
    return ".".join(str((packed >> shift) & 255) for shift in (24, 16, 8, 0))


def aggregate_host_windows(csv_path: Path, window_s: int = 60, keep_flows: bool = False):
    """Build (60s window, source host) rows. Training and inference both call this.

    Hosts need at least MIN_FLOWS, then only the busiest TOP_HOSTS in each window
    are kept. The sort key is the flow count. Labels are not used for selection.
    """
    csv_path = Path(csv_path)
    window_ms = int(window_s) * 1000
    counts, scan_meta = _pass1(csv_path, window_ms)
    selected = select_hosts(counts)
    shares = retained_flow_shares(counts, selected)
    _print_shares(shares)
    window_flows = counts.groupby("window")["n"].sum().rename("window_flows") if len(counts) else pd.Series(dtype=np.float64)
    active_hosts = counts.groupby("window")["src"].nunique().rename("active_hosts") if len(counts) else pd.Series(dtype=np.float64)
    if len(selected) == 0:
        table = pd.DataFrame(columns=["window", "src", "stage"])
        flows = pd.DataFrame(columns=["window", "src", "dst_ip", "dst_port", "protocol", "bytes", "tcp_flags"])
        meta = {
            "version": HOST_CACHE_VERSION,
            "shares": shares,
            "class_flows": scan_meta["class_flows"],
            "rows": scan_meta["rows"],
            "host_rows": 0,
            "min_flows_dropped_host_windows": int((counts["n"] < MIN_FLOWS).sum()),
            "min_ms": scan_meta["min_ms"],
            "max_ms": scan_meta["max_ms"],
            "dst_port_counts": {},
        }
        return table, meta, flows if keep_flows else None
    chosen = np.sort(_pack(selected["window"].to_numpy(), selected["src"].to_numpy(np.uint32)))
    numeric, quads, flows, port_counts = _pass2(csv_path, window_ms, chosen, keep_flows=keep_flows)
    diversity = _diversity(quads)
    del quads
    table = numeric.merge(diversity, on=["window", "src"], how="left")
    for column in ("uniq_dst", "uniq_dport", "port_scan", "top_dst_ip", "top_dst_port"):
        table[column] = table[column].fillna(0)
    labels = selected[["window", "src", *COUNT_COLS]].copy()
    table = table.drop(columns=[column for column in COUNT_COLS if column in table.columns and column != "n"], errors="ignore")
    table = table.merge(labels.drop(columns="n"), on=["window", "src"], how="left")
    table = table.merge(window_flows, left_on="window", right_index=True, how="left")
    table = table.merge(active_hosts, left_on="window", right_index=True, how="left")
    table["window_start_ms"] = table["window"].astype(np.int64) * window_ms
    table["day"] = pd.to_datetime(table["window_start_ms"], unit="ms", utc=True).dt.strftime("%Y-%m-%d")
    table = label_host_rows(table)
    table = table.sort_values(["src", "window"]).reset_index(drop=True)
    meta = {
        "version": HOST_CACHE_VERSION,
        "shares": shares,
        "class_flows": scan_meta["class_flows"],
        "rows": scan_meta["rows"],
        "host_rows": int(len(table)),
        "min_flows_dropped_host_windows": int((counts["n"] < MIN_FLOWS).sum()),
        "min_ms": scan_meta["min_ms"],
        "max_ms": scan_meta["max_ms"],
        "dst_port_counts": {str(port): int(count) for port, count in port_counts.items()} if keep_flows else {},
    }
    return table, meta, flows if keep_flows else None


def load_host_table(csv_path: Path, window_s: int = 60) -> tuple[pd.DataFrame, dict]:
    csv_path = Path(csv_path)
    cache_csv, cache_meta = _cache_paths(window_s)
    source = {"path": str(csv_path), "bytes": csv_path.stat().st_size, "min_flows": MIN_FLOWS, "top_hosts": TOP_HOSTS}
    if cache_csv.is_file() and cache_meta.is_file():
        meta = json.loads(cache_meta.read_text(encoding="utf-8"))
        if meta.get("version") == HOST_CACHE_VERSION and meta.get("source") == source:
            print(f"host cache hit {cache_csv}", flush=True)
            frame = pd.read_csv(cache_csv)
            _print_shares(meta["shares"])
            return frame, meta

    table, meta, _flows = aggregate_host_windows(csv_path, window_s=window_s, keep_flows=False)
    meta = {
        "version": HOST_CACHE_VERSION,
        "source": source,
        "shares": meta["shares"],
        "class_flows": meta["class_flows"],
        "rows": meta["rows"],
        "host_rows": meta["host_rows"],
        "min_ms": meta["min_ms"],
        "max_ms": meta["max_ms"],
    }
    table.to_csv(cache_csv, index=False, compression="gzip")
    cache_meta.write_text(json.dumps(meta), encoding="utf-8")
    print(f"cached {cache_csv} host_rows {len(table)}", flush=True)
    return table, meta


def fill_split_gaps(split_map: dict[int, str], window_s: int = 60) -> dict[int, str]:
    """Label empty minutes that sit inside one split and are not more than 10 minutes wide."""
    filled = dict(split_map)
    max_steps = GAP_MS // (int(window_s) * 1000)
    items = sorted(split_map.items())
    for (left, left_split), (right, right_split) in zip(items, items[1:]):
        gap = int(right) - int(left)
        if left_split == right_split and 1 < gap <= max_steps:
            for slot in range(int(left) + 1, int(right)):
                filled[slot] = left_split
    return filled


def network_split_map(csv_path: Path, window_s: int = 60) -> dict[int, str]:
    """Time boundaries from the network-level attack-span split, keyed by window id."""
    windows, _precheck = load_windows(csv_path, window_s=window_s)
    modeled = modeling_frame(windows)
    window_ms = int(window_s) * 1000
    keys = (modeled["window_start_ms"].to_numpy(np.int64) // window_ms).astype(np.int64)
    mapped = {int(key): str(split) for key, split in zip(keys, modeled["split"].to_numpy())}
    return fill_split_gaps(mapped, window_s)


def apply_network_split(frame: pd.DataFrame, split_map: dict[int, str]) -> pd.DataFrame:
    """Give every host in a window the same split. Unknown times stay in the purge."""
    out = frame.loc[frame["stage"] != "dropped"].copy()
    out["split"] = out["window"].map(lambda key: split_map.get(int(key), "purge")).astype(object)
    return out.reset_index(drop=True)


def host_anchors(frame: pd.DataFrame, split_map: dict[int, str], seq_len: int, future: int) -> dict[str, np.ndarray]:
    """Anchors whose history and future stay on one split. Missing host slots are allowed."""
    hosts = frame["src"].to_numpy(np.uint32)
    windows = frame["window"].to_numpy(np.int64)
    splits = frame["split"].to_numpy()
    chosen = {name: [] for name in ("train", "val", "test")}
    for index in range(len(frame)):
        split = splits[index]
        if split not in chosen:
            continue
        start = int(windows[index]) - (seq_len - 1)
        stop = int(windows[index]) + future
        if all(split_map.get(slot) == split for slot in range(start, stop + 1)):
            chosen[split].append(index)
    return {name: np.asarray(values, dtype=int) for name, values in chosen.items()}
