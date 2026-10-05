"""Stream NF-CSE-CIC-IDS2018-v3 into 60-second windows.

Aggregation is incremental: numeric sums are grouped per chunk, and unique
addresses are merged from per-chunk distinct pairs so the 20M-row file is not
held in memory. The window table is cached under ml/cache/.
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from .config import (
    ACK,
    FIN,
    FLOW_FEATURES,
    GAP_MS,
    PACKET_FEATURES,
    PSH,
    PURGE_WINDOWS,
    RST,
    SEQ_LEN,
    SYN,
    URG,
    V3_STAGES,
)

CACHE_DIR = Path(__file__).resolve().parent / "cache"
CACHE_VERSION = 1
DATE_MIN = date(2018, 2, 14)
DATE_MAX = date(2018, 3, 2)

USECOLS = [
    "FLOW_START_MILLISECONDS",
    "IPV4_SRC_ADDR",
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
    "Attack",
]

NUM_SUM_COLS = [
    "n", "in_bytes", "out_bytes", "in_pkts", "out_pkts",
    "sum_log1p_duration", "tcp_n", "udp_n", "icmp_n",
    "fin_n", "syn_n", "rst_n", "psh_n", "ack_n", "urg_n",
    "sum_min_ttl", "sum_max_ttl", "sumsq_min_ttl",
    "sum_win_in", "sum_win_out", "retrans_pkts",
    "sum_iat_mean", "sum_iat_max", "sum_iat_std",
    "n_benign", "n_initial", "n_lateral", "n_c2", "n_excluded", "n_other",
]

MAPPED_STAGES = ("initial_access", "lateral_movement", "command_and_control")


def is_netflow_v3(path: Path) -> bool:
    path = Path(path)
    if not path.is_file():
        return False
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        header = handle.readline()
    return "FLOW_START_MILLISECONDS" in header and "Attack" in header


def attack_bucket(raw) -> str:
    """Map one Attack string. Web, DoS, and DDoS are excluded from the kill chain."""
    text = str(raw).strip().lower()
    compact = text.replace(" ", "").replace("-", "").replace("_", "")
    if text in {"benign", "none", "nan", "-", ""} or compact == "benign":
        return "benign"
    if "infil" in text:
        return "lateral_movement"
    if "xss" in text or "sql" in text or "web" in text:
        return "excluded"
    if "ddos" in compact or compact.startswith("dos"):
        return "excluded"
    if "bruteforce" in compact:
        return "initial_access"
    if compact == "bot" or compact.startswith("bot"):
        return "command_and_control"
    return "other"


def passes_date_gate(min_ms: int, max_ms: int) -> tuple[bool, str]:
    start = datetime.fromtimestamp(min_ms / 1000, timezone.utc).date()
    end = datetime.fromtimestamp(max_ms / 1000, timezone.utc).date()
    ok = DATE_MIN <= start and end <= DATE_MAX
    message = f"{start.isoformat()} .. {end.isoformat()}"
    return ok, message


def _ipv4_to_uint32(series: pd.Series) -> np.ndarray:
    parts = series.astype("string").str.split(".", expand=True)
    cols = []
    for index in range(4):
        if parts.shape[1] > index:
            cols.append(pd.to_numeric(parts.iloc[:, index], errors="coerce").fillna(0).to_numpy(np.float64))
        else:
            cols.append(np.zeros(len(series), dtype=np.float64))
    packed = (
        cols[0].astype(np.uint64) << 24
        | cols[1].astype(np.uint64) << 16
        | cols[2].astype(np.uint64) << 8
        | cols[3].astype(np.uint64)
    )
    return packed.astype(np.uint32)


def _num(series: pd.Series) -> np.ndarray:
    return pd.to_numeric(series, errors="coerce").fillna(0).to_numpy(np.float64)


def prepare_chunk(frame: pd.DataFrame, window_ms: int) -> dict:
    """Aggregate one dataframe of raw flows. Used by the streamer and by tests."""
    ts = _num(frame["FLOW_START_MILLISECONDS"]).astype(np.int64)
    window = ts // int(window_ms)
    protocol = _num(frame["PROTOCOL"]).astype(np.int64)
    flags = _num(frame["TCP_FLAGS"]).astype(np.int64)
    duration = np.clip(_num(frame["FLOW_DURATION_MILLISECONDS"]), 0, None)
    in_bytes = np.clip(_num(frame["IN_BYTES"]), 0, None)
    out_bytes = np.clip(_num(frame["OUT_BYTES"]), 0, None)
    in_pkts = np.clip(_num(frame["IN_PKTS"]), 0, None)
    out_pkts = np.clip(_num(frame["OUT_PKTS"]), 0, None)
    min_ttl = _num(frame["MIN_TTL"])
    max_ttl = _num(frame["MAX_TTL"])
    retrans = np.clip(_num(frame["RETRANSMITTED_IN_PKTS"]), 0, None) + np.clip(_num(frame["RETRANSMITTED_OUT_PKTS"]), 0, None)
    win_in = np.clip(_num(frame["TCP_WIN_MAX_IN"]), 0, None)
    win_out = np.clip(_num(frame["TCP_WIN_MAX_OUT"]), 0, None)
    iat_mean = (np.clip(_num(frame["SRC_TO_DST_IAT_AVG"]), 0, None) + np.clip(_num(frame["DST_TO_SRC_IAT_AVG"]), 0, None)) / 2
    iat_max = np.maximum(np.clip(_num(frame["SRC_TO_DST_IAT_MAX"]), 0, None), np.clip(_num(frame["DST_TO_SRC_IAT_MAX"]), 0, None))
    iat_std = (np.clip(_num(frame["SRC_TO_DST_IAT_STDDEV"]), 0, None) + np.clip(_num(frame["DST_TO_SRC_IAT_STDDEV"]), 0, None)) / 2
    tcp = protocol == 6
    buckets = frame["Attack"].map(attack_bucket).to_numpy()
    work = pd.DataFrame({
        "window": window,
        "n": 1,
        "in_bytes": in_bytes,
        "out_bytes": out_bytes,
        "in_pkts": in_pkts,
        "out_pkts": out_pkts,
        "sum_log1p_duration": np.log1p(duration),
        "tcp_n": tcp.astype(np.int64),
        "udp_n": (protocol == 17).astype(np.int64),
        "icmp_n": (protocol == 1).astype(np.int64),
        "fin_n": (tcp & ((flags & FIN) != 0)).astype(np.int64),
        "syn_n": (tcp & ((flags & SYN) != 0)).astype(np.int64),
        "rst_n": (tcp & ((flags & RST) != 0)).astype(np.int64),
        "psh_n": (tcp & ((flags & PSH) != 0)).astype(np.int64),
        "ack_n": (tcp & ((flags & ACK) != 0)).astype(np.int64),
        "urg_n": (tcp & ((flags & URG) != 0)).astype(np.int64),
        "sum_min_ttl": min_ttl,
        "sum_max_ttl": max_ttl,
        "sumsq_min_ttl": min_ttl * min_ttl,
        "sum_win_in": win_in,
        "sum_win_out": win_out,
        "retrans_pkts": retrans,
        "sum_iat_mean": iat_mean,
        "sum_iat_max": iat_max,
        "sum_iat_std": iat_std,
        "n_benign": (buckets == "benign").astype(np.int64),
        "n_initial": (buckets == "initial_access").astype(np.int64),
        "n_lateral": (buckets == "lateral_movement").astype(np.int64),
        "n_c2": (buckets == "command_and_control").astype(np.int64),
        "n_excluded": (buckets == "excluded").astype(np.int64),
        "n_other": (buckets == "other").astype(np.int64),
        "src": _ipv4_to_uint32(frame["IPV4_SRC_ADDR"]),
        "dst": _ipv4_to_uint32(frame["IPV4_DST_ADDR"]),
        "dport": _num(frame["L4_DST_PORT"]).astype(np.int32),
    })
    numeric = work.groupby("window", sort=False)[NUM_SUM_COLS].sum()
    return {
        "numeric": numeric,
        "src": work.drop_duplicates(["window", "src"])[["window", "src"]],
        "dst": work.drop_duplicates(["window", "dst"])[["window", "dst"]],
        "ports": work.drop_duplicates(["window", "dport"])[["window", "dport"]],
        "scan": work.drop_duplicates(["window", "src", "dport"])[["window", "src", "dport"]],
        "rows": int(len(frame)),
    }


def _merge_parts(parts: list[pd.DataFrame], keys: list[str]) -> pd.DataFrame:
    if not parts:
        return pd.DataFrame(columns=keys)
    merged = pd.concat(parts, ignore_index=True)
    return merged.drop_duplicates(keys)


def _compact(parts: list[pd.DataFrame], keys: list[str], limit: int = 4) -> list[pd.DataFrame]:
    if len(parts) < limit:
        return parts
    return [_merge_parts(parts, keys)]


def label_windows(frame: pd.DataFrame, min_attack_frac: float) -> pd.DataFrame:
    """Drop DoS/DDoS/Web windows above the fraction. Else map the dominant proxy stage."""
    out = frame.copy()
    total = np.maximum(out["n"].to_numpy(np.float64), 1.0)
    excluded_share = out["n_excluded"].to_numpy(np.float64) / total
    mapped = out[["n_initial", "n_lateral", "n_c2"]].to_numpy(np.float64)
    mapped_share = mapped.sum(axis=1) / total
    top = mapped.argmax(axis=1)
    names = np.asarray(MAPPED_STAGES, dtype=object)
    stage = np.where(mapped_share >= float(min_attack_frac), names[top], "benign")
    stage = np.where(excluded_share > float(min_attack_frac), "dropped", stage)
    out["stage"] = stage
    return out


def _label_fraction(count: int, purge: int) -> np.ndarray:
    """First 60% train, next 15% val, last 25% test, with a purge gap before val and before test."""
    labels = np.array(["purge"] * count, dtype=object)
    cut1 = int(count * 0.60)
    cut2 = int(count * 0.75)
    train_end = cut1 - purge
    val_end = cut2 - purge
    if train_end > 0:
        labels[:train_end] = "train"
    if val_end > cut1:
        labels[cut1:val_end] = "val"
    if cut2 < count:
        labels[cut2:] = "test"
    return labels


def assign_splits(frame: pd.DataFrame, purge: int = PURGE_WINDOWS) -> pd.DataFrame:
    """Split each capture day without leaving an attack class only in the morning.

    A day with attack windows uses the span from the first attack window through the
    last. Windows before that span are train. The span itself is 60/15/25 with purge
    gaps. Windows after the span are test. A day with no attack windows stays 60/15/25.
    """
    out = frame.sort_values(["day", "window_start_ms"]).reset_index(drop=True)
    split = np.array(["purge"] * len(out), dtype=object)
    attack_names = np.asarray(MAPPED_STAGES, dtype=object)
    for _, index in out.groupby("day", sort=False).groups.items():
        positions = np.asarray(list(index), dtype=int)
        stages = out.loc[positions, "stage"].to_numpy()
        attack_at = np.flatnonzero(np.isin(stages, attack_names))
        if len(attack_at) == 0:
            split[positions] = _label_fraction(len(positions), purge)
            continue
        first = int(attack_at[0])
        last = int(attack_at[-1])
        labels = np.array(["train"] * len(positions), dtype=object)
        labels[first:last + 1] = _label_fraction(last - first + 1, purge)
        if last + 1 < len(labels):
            labels[last + 1:] = "test"
        split[positions] = labels
    out["split"] = split
    return out


def sequence_anchors(frame: pd.DataFrame, split: str, seq_len: int = SEQ_LEN, future: int = 5) -> np.ndarray:
    """Current-window positions whose history and future stay in one split and one 10-minute run."""
    chosen = []
    for _, index in frame.groupby("day", sort=False).groups.items():
        positions = np.asarray(list(index), dtype=int)
        if len(positions) and int(positions[-1] - positions[0] + 1) != len(positions):
            raise RuntimeError("Capture-day windows are not a contiguous block.")
        starts = frame.loc[positions, "window_start_ms"].to_numpy(np.int64)
        splits = frame.loc[positions, "split"].to_numpy()
        count = len(positions)
        for local in range(count):
            lo = local - (seq_len - 1)
            hi = local + future
            if lo < 0 or hi >= count:
                continue
            if not np.all(splits[lo:hi + 1] == split):
                continue
            deltas = np.diff(starts[lo:hi + 1])
            if np.any(deltas > GAP_MS):
                continue
            chosen.append(int(positions[local]))
    return np.asarray(chosen, dtype=int)


def build_feature_frame(frame: pd.DataFrame) -> pd.DataFrame:
    total = np.maximum(frame["n"].to_numpy(np.float64), 1.0)
    tcp = frame["tcp_n"].to_numpy(np.float64)
    in_bytes = frame["in_bytes"].to_numpy(np.float64)
    out_bytes = frame["out_bytes"].to_numpy(np.float64)
    ratio = np.divide(out_bytes, in_bytes, out=np.zeros_like(out_bytes), where=in_bytes > 0)
    ratio = np.where((in_bytes <= 0) & (out_bytes > 0), out_bytes, ratio)
    pkts = frame["in_pkts"].to_numpy(np.float64) + frame["out_pkts"].to_numpy(np.float64)
    retrans_pkts = frame["retrans_pkts"].to_numpy(np.float64)
    retrans = np.minimum(np.divide(retrans_pkts, pkts, out=np.zeros_like(pkts), where=pkts > 0), 1.0)
    mean_min = frame["sum_min_ttl"].to_numpy(np.float64) / total
    mean_max = frame["sum_max_ttl"].to_numpy(np.float64) / total
    variance = np.maximum(frame["sumsq_min_ttl"].to_numpy(np.float64) / total - mean_min ** 2, 0.0)

    def flag(name_count: str) -> np.ndarray:
        counts = frame[name_count].to_numpy(np.float64)
        return np.divide(counts, tcp, out=np.zeros_like(counts), where=tcp > 0)

    data = {
        "log1p_n_flows": np.log1p(frame["n"].to_numpy(np.float64)),
        "log1p_in_bytes": np.log1p(in_bytes),
        "log1p_out_bytes": np.log1p(out_bytes),
        "log1p_in_pkts": np.log1p(frame["in_pkts"].to_numpy(np.float64)),
        "log1p_out_pkts": np.log1p(frame["out_pkts"].to_numpy(np.float64)),
        "log1p_out_in_byte_ratio": np.log1p(np.clip(ratio, 0, None)),
        "mean_log1p_duration": frame["sum_log1p_duration"].to_numpy(np.float64) / total,
        "fin_ratio": flag("fin_n"),
        "syn_ratio": flag("syn_n"),
        "rst_ratio": flag("rst_n"),
        "psh_ratio": flag("psh_n"),
        "ack_ratio": flag("ack_n"),
        "urg_ratio": flag("urg_n"),
        "tcp_share": tcp / total,
        "udp_share": frame["udp_n"].to_numpy(np.float64) / total,
        "icmp_share": frame["icmp_n"].to_numpy(np.float64) / total,
        "log1p_uniq_src_ips": np.log1p(frame["uniq_src"].to_numpy(np.float64)),
        "log1p_uniq_dst_ips": np.log1p(frame["uniq_dst"].to_numpy(np.float64)),
        "log1p_uniq_dst_ports": np.log1p(frame["uniq_dport"].to_numpy(np.float64)),
        "log1p_port_scan_score": np.log1p(frame["port_scan"].to_numpy(np.float64)),
        "mean_min_ttl": mean_min,
        "mean_max_ttl": mean_max,
        "log1p_ttl_var": np.log1p(variance),
        "log1p_mean_tcp_win_max_in": np.log1p(frame["sum_win_in"].to_numpy(np.float64) / total),
        "log1p_mean_tcp_win_max_out": np.log1p(frame["sum_win_out"].to_numpy(np.float64) / total),
        "retrans_ratio": retrans,
        "log1p_iat_mean": np.log1p(frame["sum_iat_mean"].to_numpy(np.float64) / total),
        "log1p_iat_max": np.log1p(frame["sum_iat_max"].to_numpy(np.float64) / total),
        "log1p_iat_std": np.log1p(frame["sum_iat_std"].to_numpy(np.float64) / total),
    }
    ordered = FLOW_FEATURES + PACKET_FEATURES
    return pd.DataFrame({name: data[name] for name in ordered})


def _cache_paths(window_s: int) -> tuple[Path, Path]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    stem = f"netflow_v3_w{int(window_s)}_v{CACHE_VERSION}"
    return CACHE_DIR / f"{stem}.csv.gz", CACHE_DIR / f"{stem}.meta.json"


def _print_precheck(precheck: dict) -> None:
    print("PRECHECK", flush=True)
    print(f"rows {precheck['rows']}", flush=True)
    print(f"utc_min {precheck['utc_min']}", flush=True)
    print(f"utc_max {precheck['utc_max']}", flush=True)
    print(f"date_span {precheck['date_span']}", flush=True)
    print(
        f"out_of_order_rows {precheck['out_of_order_rows']} "
        f"pairs {precheck['order_pairs']} fraction {precheck['out_of_order_fraction']:.8f}",
        flush=True,
    )
    print("attack_value_counts", flush=True)
    for name, count in precheck["attack_counts"]:
        print(f"  {name!r} {count}", flush=True)


def _finalize_windows(numeric_parts, src_parts, dst_parts, port_parts, scan_parts, window_ms: int, min_attack_frac: float) -> pd.DataFrame:
    numeric = pd.concat(numeric_parts).groupby(level=0).sum()
    src = _merge_parts(src_parts, ["window", "src"]).groupby("window").size().rename("uniq_src")
    dst = _merge_parts(dst_parts, ["window", "dst"]).groupby("window").size().rename("uniq_dst")
    ports = _merge_parts(port_parts, ["window", "dport"]).groupby("window").size().rename("uniq_dport")
    scan = _merge_parts(scan_parts, ["window", "src", "dport"])
    if len(scan):
        scan_score = scan.groupby(["window", "src"]).size().groupby("window").max().rename("port_scan")
    else:
        scan_score = pd.Series(dtype=np.int64, name="port_scan")
    table = numeric.join(src, how="left").join(dst, how="left").join(ports, how="left").join(scan_score, how="left")
    for column in ("uniq_src", "uniq_dst", "uniq_dport", "port_scan"):
        table[column] = table[column].fillna(0).astype(np.int64)
    table = table.reset_index(names="window")
    table["window_start_ms"] = table["window"].astype(np.int64) * int(window_ms)
    table["day"] = pd.to_datetime(table["window_start_ms"], unit="ms", utc=True).dt.strftime("%Y-%m-%d")
    table = label_windows(table, min_attack_frac)
    return table.sort_values("window_start_ms").reset_index(drop=True)


def load_windows(csv_path: Path, window_s: int = 60, min_attack_frac: float = 0.05) -> tuple[pd.DataFrame, dict]:
    csv_path = Path(csv_path)
    window_ms = int(window_s) * 1000
    cache_csv, cache_meta = _cache_paths(window_s)
    source = {"path": str(csv_path), "bytes": csv_path.stat().st_size, "min_attack_frac": float(min_attack_frac)}
    if cache_csv.is_file() and cache_meta.is_file():
        meta = json.loads(cache_meta.read_text(encoding="utf-8"))
        if meta.get("version") == CACHE_VERSION and meta.get("source") == source:
            print(f"cache hit {cache_csv}", flush=True)
            frame = pd.read_csv(cache_csv)
            precheck = meta["precheck"]
            _print_precheck(precheck)
            _print_day_stage(frame)
            return frame, precheck

    counts: Counter = Counter()
    min_ms = None
    max_ms = None
    prev = None
    order_pairs = 0
    out_of_order = 0
    rows = 0
    numeric_parts = []
    src_parts, dst_parts, port_parts, scan_parts = [], [], [], []
    reader = pd.read_csv(csv_path, usecols=USECOLS, chunksize=1_000_000)
    for index, chunk in enumerate(reader):
        ts = _num(chunk["FLOW_START_MILLISECONDS"]).astype(np.int64)
        if len(ts):
            lo = int(ts.min())
            hi = int(ts.max())
            min_ms = lo if min_ms is None else min(min_ms, lo)
            max_ms = hi if max_ms is None else max(max_ms, hi)
            if prev is not None:
                order_pairs += 1
                if int(ts[0]) < prev:
                    out_of_order += 1
            if len(ts) > 1:
                out_of_order += int(np.sum(ts[1:] < ts[:-1]))
                order_pairs += len(ts) - 1
            prev = int(ts[-1])
        counts.update(chunk["Attack"].astype(str).value_counts().to_dict())
        prepared = prepare_chunk(chunk, window_ms)
        numeric_parts.append(prepared["numeric"])
        src_parts.append(prepared["src"])
        dst_parts.append(prepared["dst"])
        port_parts.append(prepared["ports"])
        scan_parts.append(prepared["scan"])
        src_parts = _compact(src_parts, ["window", "src"])
        dst_parts = _compact(dst_parts, ["window", "dst"])
        port_parts = _compact(port_parts, ["window", "dport"])
        scan_parts = _compact(scan_parts, ["window", "src", "dport"])
        rows += prepared["rows"]
        print(f"chunk {index} rows {prepared['rows']} total_rows {rows}", flush=True)
        del chunk, prepared

    if min_ms is None or max_ms is None:
        raise RuntimeError(f"No flow timestamps in {csv_path}")
    ok, span = passes_date_gate(min_ms, max_ms)
    utc_min = datetime.fromtimestamp(min_ms / 1000, timezone.utc).isoformat()
    utc_max = datetime.fromtimestamp(max_ms / 1000, timezone.utc).isoformat()
    precheck = {
        "rows": rows,
        "utc_min": utc_min,
        "utc_max": utc_max,
        "date_span": span,
        "date_gate_ok": ok,
        "out_of_order_rows": out_of_order,
        "order_pairs": order_pairs,
        "out_of_order_fraction": float(out_of_order / max(order_pairs, 1)),
        "attack_counts": counts.most_common(),
        "window_s": int(window_s),
    }
    _print_precheck(precheck)
    if not ok:
        print(f"STOP flow-start dates {span} are outside 2018-02-14..2018-03-02", flush=True)
        raise SystemExit(2)

    frame = _finalize_windows(numeric_parts, src_parts, dst_parts, port_parts, scan_parts, window_ms, min_attack_frac)
    _print_day_stage(frame)
    frame.to_csv(cache_csv, index=False, compression="gzip")
    cache_meta.write_text(json.dumps({"version": CACHE_VERSION, "source": source, "precheck": precheck}, indent=2), encoding="utf-8")
    print(f"cached {cache_csv}", flush=True)
    return frame, precheck


def _print_day_stage(frame: pd.DataFrame) -> None:
    print("windows_per_stage_per_day", flush=True)
    counts = frame.groupby(["day", "stage"], sort=True).size()
    for (day, stage), count in counts.items():
        print(f"  {day} {stage} {int(count)}", flush=True)


def modeling_frame(frame: pd.DataFrame) -> pd.DataFrame:
    kept = frame[frame["stage"] != "dropped"].copy()
    unknown = sorted(set(kept["stage"]) - set(V3_STAGES))
    if unknown:
        raise RuntimeError(f"Unexpected stages after labelling: {unknown}")
    return assign_splits(kept)


def coverage_sentence(frame: pd.DataFrame) -> str:
    days = {
        stage: sorted(frame.loc[frame["stage"] == stage, "day"].unique())
        for stage in MAPPED_STAGES
    }
    brute = days["initial_access"]
    bot = days["command_and_control"]
    if len(brute) == 1 and len(bot) == 1:
        return "BruteForce appears on one capture day and Bot on one."
    return (
        f"BruteForce windows appear on {len(brute)} capture day(s) ({', '.join(brute) or 'none'}); "
        f"Bot windows appear on {len(bot)} capture day(s) ({', '.join(bot) or 'none'})."
    )
