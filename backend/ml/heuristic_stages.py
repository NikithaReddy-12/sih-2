"""Rule-based stage signals kept separate from the learned host model."""
from __future__ import annotations

from collections import defaultdict
import math

from .host_v3 import ipv4_from_uint32

SINGLE_WINDOW_UNIQ_DST_PORTS = 200

# thresholds were set from feature semantics, and the reconnaissance rule was adjusted once after the first synthetic demo scan was missed; they are demonstration rules, not benchmark-tuned.
THRESHOLDS = {
    "reconnaissance": {
        "log1p_port_scan_score": math.log1p(20),
        "log1p_uniq_dst_ports": math.log1p(20),
        "top_dst_port_share_max": 0.15,
        "small_flow_share_min": 0.75,
        "no_response_share_min": 0.75,
        "required_windows": 2,
        "lookback_windows": 3,
    },
    "exfiltration": {
        "log1p_out_in_byte_ratio": math.log1p(8),
        "mean_log_out_bytes_min": 8.0,
        "top_dst_ip_share_min": 0.90,
        "required_consecutive_windows": 3,
    },
}

RECON_STAGE = {"stage": "reconnaissance", "tactic": "Reconnaissance", "mitre_id": "TA0043"}
EXFIL_STAGE = {"stage": "exfiltration", "tactic": "Exfiltration", "mitre_id": "TA0010"}


def _recon_window(row) -> bool:
    thresholds = THRESHOLDS["reconnaissance"]
    scan_shape = (
        float(row["log1p_port_scan_score"]) >= thresholds["log1p_port_scan_score"]
        and float(row["log1p_uniq_dst_ports"]) >= thresholds["log1p_uniq_dst_ports"]
        and float(row["top_dst_port_share"]) <= thresholds["top_dst_port_share_max"]
    )
    traffic_shape = (
        float(row["small_flow_share"]) >= thresholds["small_flow_share_min"]
        or float(row["no_response_share"]) >= thresholds["no_response_share_min"]
    )
    return scan_shape and traffic_shape


def _single_window_burst(row) -> bool:
    thresholds = THRESHOLDS["reconnaissance"]
    return (
        float(row["log1p_uniq_dst_ports"]) >= math.log1p(SINGLE_WINDOW_UNIQ_DST_PORTS)
        and float(row["top_dst_port_share"]) <= thresholds["top_dst_port_share_max"]
        and float(row["small_flow_share"]) >= thresholds["small_flow_share_min"]
    )


def _exfil_window(row) -> bool:
    thresholds = THRESHOLDS["exfiltration"]
    return (
        float(row["log1p_out_in_byte_ratio"]) >= thresholds["log1p_out_in_byte_ratio"]
        and float(row["mean_log_out_bytes"]) >= thresholds["mean_log_out_bytes_min"]
        and float(row["top_dst_ip_share"]) >= thresholds["top_dst_ip_share_min"]
    )


def _consecutive_runs(windows: list[int]) -> list[list[int]]:
    if not windows:
        return []
    runs = [[windows[0]]]
    for window in windows[1:]:
        if window == runs[-1][-1] + 1:
            runs[-1].append(window)
        else:
            runs.append([window])
    return runs


def _recon_hit(host: str, rows: list[dict]) -> dict | None:
    recent = rows[-THRESHOLDS["reconnaissance"]["lookback_windows"]:]
    fired = [row for row in recent if _recon_window(row)]
    mode = "persistent"
    if len(fired) < THRESHOLDS["reconnaissance"]["required_windows"]:
        burst = next((row for row in reversed(recent) if _single_window_burst(row)), None)
        if burst is None:
            return None
        fired = [burst]
        mode = "single_window_burst"
    return {
        **RECON_STAGE,
        "host": host,
        "score": round(len(fired) / len(recent), 6) if mode == "persistent" else 0.333333,
        "source": "heuristic",
        "rule_values": {
            "mode": mode,
            "fired_windows": [int(row["window"]) for row in fired],
            "log1p_port_scan_score": [float(row["log1p_port_scan_score"]) for row in fired],
            "log1p_uniq_dst_ports": [float(row["log1p_uniq_dst_ports"]) for row in fired],
            "top_dst_port_share": [float(row["top_dst_port_share"]) for row in fired],
            "small_flow_share": [float(row["small_flow_share"]) for row in fired],
            "no_response_share": [float(row["no_response_share"]) for row in fired],
        },
        "trigger_windows": [int(row["window"]) for row in fired],
    }


def _exfil_hit(host: str, rows: list[dict]) -> dict | None:
    fired_windows = [int(row["window"]) for row in rows if _exfil_window(row)]
    runs = _consecutive_runs(fired_windows)
    runs = [run for run in runs if len(run) >= THRESHOLDS["exfiltration"]["required_consecutive_windows"]]
    if not runs:
        return None
    trigger = max(runs, key=len)
    fired = {int(row["window"]): row for row in rows}
    return {
        **EXFIL_STAGE,
        "host": host,
        "score": round(min(1.0, len(trigger) / 10.0), 6),
        "source": "heuristic",
        "rule_values": {
            "fired_windows": trigger,
            "log1p_out_in_byte_ratio": [float(fired[window]["log1p_out_in_byte_ratio"]) for window in trigger],
            "mean_log_out_bytes": [float(fired[window]["mean_log_out_bytes"]) for window in trigger],
            "top_dst_ip_share": [float(fired[window]["top_dst_ip_share"]) for window in trigger],
            "dst_is_private": [bool(fired[window].get("dst_is_private", False)) for window in trigger],
        },
        "trigger_windows": trigger,
    }


def detect_heuristic_stages(features) -> dict:
    """Return separate heuristic host and timeline hits from host-window features."""
    by_host = defaultdict(list)
    for row in features.sort_values(["src", "window"]).to_dict("records"):
        by_host[int(row["src"])].append(row)
    host_hits = []
    timeline_hits = defaultdict(list)
    for source, rows in by_host.items():
        host = ipv4_from_uint32(source)
        hits = [_recon_hit(host, rows), _exfil_hit(host, rows)]
        for hit in (item for item in hits if item is not None):
            host_hits.append(hit)
            for window in hit["trigger_windows"]:
                timeline_hits[window].append({key: value for key, value in hit.items() if key != "trigger_windows"})
    for hit in host_hits:
        hit.pop("trigger_windows", None)
    return {"hosts": host_hits, "timeline": dict(timeline_hits)}
