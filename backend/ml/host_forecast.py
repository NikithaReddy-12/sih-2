"""Host-level NetFlow-V3 forecast. Uses the same window aggregation as training."""
from __future__ import annotations

import gzip
import ipaddress
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import torch

from .baseline import MODELS_DIR
from .config import ACK, FIN, PSH, ROLLOUT_K, RST, SEQ_LEN, SYN, URG
from .host_train import stack_host
from .host_v3 import (
    CONCENTRATION_FEATURES,
    CONTEXT_FEATURES,
    FLOW_FEATURES,
    PACKET_FEATURES,
    PASS2_COLS,
    aggregate_host_windows,
    build_host_features,
    ipv4_from_uint32,
)
from .model_v3 import load_lstm, transform_matrix
from .heuristic_stages import detect_heuristic_stages
from .stages import describe

HOST_LSTM_NAME = "v3_host_lstm_seed0.pt"
FLAG_BASIS = "future"
CURRENT_OBSERVED_WINDOWS = 3
NETWORK_RISK_DEFINITION = (
    "highest host attack probability in the window (max over hosts of 1 - P(benign)); "
    "this is not a calibrated probability and false alarms accumulate across hosts"
)
HOST_MODE = "netflow_v3_host"
REPLAY_NOTE = (
    "composed replay of real test windows from three different captures, not a single real attack"
)
NOT_PREDICTED = ()
HEURISTIC_STAGES = ("reconnaissance", "exfiltration")
MITRE_TABLE = [
    {"stage": "initial_access", "tactic": "Initial Access", "mitre_id": "TA0001"},
    {"stage": "lateral_movement", "tactic": "Lateral Movement", "mitre_id": "TA0008"},
    {"stage": "command_and_control", "tactic": "Command and Control", "mitre_id": "TA0011"},
]
PROTOCOL_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
FLAG_BITS = (("FIN", FIN), ("SYN", SYN), ("RST", RST), ("PSH", PSH), ("ACK", ACK), ("URG", URG))
_bundle = None


def required_columns() -> list[str]:
    return list(PASS2_COLS)


def read_header(path: Path) -> list[str]:
    path = Path(path)
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace", newline="") as handle:
        line = handle.readline()
    if not line:
        return []
    return [column.strip().strip('"') for column in line.split(",")]


def missing_required_columns(header: list[str]) -> list[str]:
    present = set(header)
    return [name for name in required_columns() if name not in present]


def feature_group(name: str) -> str:
    if name in FLOW_FEATURES:
        return "FLOW"
    if name in PACKET_FEATURES:
        return "PACKET"
    if name in CONCENTRATION_FEATURES:
        return "CONCENTRATION"
    if name in CONTEXT_FEATURES:
        return "CONTEXT"
    raise ValueError(f"Unknown host feature group: {name}")


def decode_tcp_flags(flags: int) -> str:
    names = [label for label, bit in FLAG_BITS if int(flags) & bit]
    return ",".join(names)


def decode_protocol(protocol: int) -> str:
    return PROTOCOL_NAMES.get(int(protocol), str(int(protocol)))


def load_host_lstm():
    global _bundle
    if _bundle is None:
        path = MODELS_DIR / HOST_LSTM_NAME
        if not path.is_file():
            raise RuntimeError(f"{HOST_LSTM_NAME} is missing.")
        _bundle = load_lstm(path)
    return _bundle


def _lookup(frame: pd.DataFrame) -> dict[tuple[int, int], int]:
    hosts = frame["src"].to_numpy(np.uint32)
    windows = frame["window"].to_numpy(np.int64)
    return {(int(hosts[index]), int(windows[index])): index for index in range(len(frame))}


def _scale(frame: pd.DataFrame, features: list[str], clip: dict, scaler) -> np.ndarray:
    built = build_host_features(frame)
    missing = [name for name in features if name not in built.columns]
    if missing:
        raise RuntimeError("Host feature builder is missing artifact features: " + ", ".join(missing))
    raw = built[features].to_numpy(np.float64)
    return transform_matrix(raw, features, clip, scaler)


def sequence_probabilities(model, seqs: np.ndarray, k: int, n_stages: int) -> np.ndarray:
    """Return (anchors, k+1, stages) probabilities. Step 0 is the anchor window."""
    out = np.zeros((len(seqs), k + 1, n_stages), np.float32)
    if len(seqs) == 0:
        return out
    model.eval()
    with torch.no_grad():
        for start in range(0, len(seqs), 256):
            batch = torch.tensor(seqs[start:start + 256], dtype=torch.float32)
            now, future, _nxt = model(batch, k)
            now_p = torch.softmax(now, dim=-1).cpu().numpy()
            stop = start + len(batch)
            out[start:stop, 0] = now_p
            if k:
                out[start:stop, 1:] = torch.softmax(future, dim=-1).cpu().numpy()
    return out


def attribute_sequence(model, seq: np.ndarray, stage_index: int, step: int, k: int) -> np.ndarray:
    """Gradient x input of predicted-stage log-odds for one host sequence."""
    model.eval()
    x = torch.tensor(seq[None], dtype=torch.float32, requires_grad=True)
    now, future, _nxt = model(x, k)
    logits = now if int(step) <= 0 else future[:, int(step) - 1]
    other_logits = torch.cat((logits[:, :int(stage_index)], logits[:, int(stage_index) + 1:]), dim=-1)
    score = logits[:, int(stage_index)] - torch.logsumexp(other_logits, dim=-1)
    model.zero_grad(set_to_none=True)
    if x.grad is not None:
        x.grad = None
    score.backward()
    product = (x.grad * x).detach().cpu().numpy()[0]
    return np.asarray(product, dtype=np.float64)


def stage_probability(model, seq: np.ndarray, stage_index: int, step: int, k: int) -> float:
    model.eval()
    with torch.no_grad():
        x = torch.tensor(seq[None], dtype=torch.float32)
        now, future, _nxt = model(x, k)
        logits = now if int(step) <= 0 else future[:, int(step) - 1]
        prob = torch.softmax(logits, dim=-1)[0, int(stage_index)]
    return float(prob)


def top_attributions(product: np.ndarray, features: list[str], limit: int = 5) -> list[dict]:
    if product.size == 0:
        return []
    signed = product.sum(axis=0)
    order = np.argsort(-signed)
    total_abs = float(np.abs(signed).sum())

    def significant(value: float) -> float:
        return float(f"{float(value):.6g}")

    rows = []
    for index in order[:limit]:
        column = product[:, int(index)]
        timestep = int(np.argmax(np.abs(column))) if len(column) else 0
        name = features[int(index)]
        attribution = float(signed[int(index)])
        rows.append({
            "name": name,
            "shap": significant(attribution),
            "attribution": significant(attribution),
            "value": significant(float(product[timestep, int(index)])),
            "share": significant(abs(attribution) / total_abs) if total_abs else 0.0,
            "kind": feature_group(name),
            "group": feature_group(name),
            "timestep": timestep,
        })
    return rows


def _attack_stage(probabilities: np.ndarray, stages: list[str]) -> str:
    benign = stages.index("benign") if "benign" in stages else 0
    order = np.argsort(-probabilities)
    for index in order:
        if int(index) != benign:
            return stages[int(index)]
    return stages[benign]


def _window_time(window: int, window_ms: int) -> str:
    return pd.Timestamp(int(window) * int(window_ms), unit="ms", tz="UTC").isoformat()


def _flagged_flows(flows: pd.DataFrame, host: int, window: int, port_counts: dict, limit: int = 5) -> list[dict]:
    if flows is None or len(flows) == 0:
        return []
    mask = (flows["src"].to_numpy(np.uint32) == np.uint32(host)) & (flows["window"].to_numpy(np.int64) == int(window))
    chosen = flows.loc[mask]
    if len(chosen) == 0:
        return []
    rarity = chosen["dst_port"].map(lambda port: int(port_counts.get(int(port), port_counts.get(str(int(port)), 0))))
    ranked = chosen.assign(_rarity=rarity.to_numpy()).sort_values(["_rarity", "bytes"], ascending=[True, False])
    rows = []
    for _, flow in ranked.head(limit).iterrows():
        rows.append({
            "src_ip": ipv4_from_uint32(int(host)),
            "dst_ip": str(flow["dst_ip"]),
            "dst_port": int(flow["dst_port"]),
            "protocol": decode_protocol(flow["protocol"]),
            "bytes": float(flow["bytes"]),
            "tcp_flags": decode_tcp_flags(flow["tcp_flags"]),
        })
    return rows


def _mode_stage(names: list[str], preferred: str) -> str:
    counts: dict[str, int] = {}
    for name in names:
        counts[name] = counts.get(name, 0) + 1
    best = max(counts.values())
    tied = [name for name, count in counts.items() if count == best]
    if preferred in tied:
        return preferred
    return tied[0]


def _host_card(host, peak, stage_name, model, seq, features, stages, step, k, per_step, flows, port_counts, window, explanation_source: str) -> dict:
    described = describe(stage_name)
    product = attribute_sequence(model, seq, stages.index(stage_name), step, k)
    return {
        "host": ipv4_from_uint32(host),
        "peak_attack_prob": round(float(peak), 3),
        "stage": stage_name,
        "mitre_tactic": described["tactic"],
        "mitre_id": described["mitre_id"],
        "per_step_attack_prob": per_step,
        "explanation": top_attributions(product, features, 5),
        "explanation_source": explanation_source,
        "flows_in_flagged_window": _flagged_flows(flows, host, int(window), port_counts or {}, 5),
        "_peak": float(peak),
    }


def _trim_hosts(rows: list[dict]) -> list[dict]:
    rows.sort(key=lambda row: -row["_peak"])
    kept = rows[:20]
    for row in kept:
        row.pop("_peak", None)
    return kept


def _stage_summary(table: pd.DataFrame, forecast: list[dict], stages: list[str]) -> dict:
    attack_stages = set(stages) - {"benign"}
    labelled = {}
    labelled_rows = table.loc[table["stage"].isin(attack_stages)]
    for host, group in labelled_rows.groupby("src"):
        counts = group["stage"].value_counts()
        labelled[ipv4_from_uint32(int(host))] = str(counts.index[0])
    flagged = forecast
    matched = sum(
        1 for row in flagged
        if row["host"] in labelled and row["stage"] == labelled[row["host"]]
    )
    flagged_unlabelled = sum(
        1 for row in flagged
        if row["host"] not in labelled
    )
    return {
        "stage_matched": matched,
        "stage_total": len(labelled),
        "flagged_unlabelled": flagged_unlabelled,
    }


def forecast_host_frame(table: pd.DataFrame, flows, port_counts: dict, k: int = ROLLOUT_K, replay: bool = False) -> dict:
    """Score one aggregated host table with the seed-0 host LSTM."""
    bundle = load_host_lstm()
    model = bundle["model"]
    features = list(bundle["features"])
    stages = list(bundle["stages"])
    if features[-1] != "active":
        raise RuntimeError("Host artifact must keep active as the last feature so a missing slot is a zero vector.")
    kept = table.loc[table["stage"] != "dropped"].reset_index(drop=True) if "stage" in table.columns else table
    if len(kept) == 0:
        raise ValueError("No host windows to forecast after the top-host filter.")
    scaled = _scale(kept, features, bundle["clip_high"], bundle["scaler"])
    hosts = kept["src"].to_numpy(np.uint32)
    windows = kept["window"].to_numpy(np.int64)
    pos = _lookup(kept)
    anchors = np.arange(len(kept), dtype=np.int64)
    seqs, _nxt, _ys = stack_host(
        scaled, hosts, windows, np.zeros(len(kept), np.int64), anchors, pos, SEQ_LEN, k,
    )
    heuristic_features = build_host_features(kept)
    heuristic_features["window"] = windows
    heuristic_features["src"] = hosts
    heuristic_features["dst_is_private"] = False
    if flows is not None and len(flows):
        def is_private_destination(value: str) -> bool:
            address = ipaddress.ip_address(value)
            return address.is_private and (
                address in ipaddress.ip_network("10.0.0.0/8")
                or address in ipaddress.ip_network("172.16.0.0/12")
                or address in ipaddress.ip_network("192.168.0.0/16")
                or address.is_link_local
            )

        destinations = flows.assign(
            dst_private=flows["dst_ip"].map(is_private_destination),
        ).groupby(["window", "src", "dst_ip"], sort=False).agg(
            count=("dst_ip", "size"),
            dst_private=("dst_private", "first"),
        ).reset_index()
        top_destinations = destinations.loc[destinations.groupby(["window", "src"])["count"].idxmax()]
        private_by_window = {
            (int(row.window), int(row.src)): bool(row.dst_private)
            for row in top_destinations.itertuples()
        }
        heuristic_features["dst_is_private"] = [
            private_by_window.get((int(window), int(host)), False)
            for window, host in zip(windows, hosts)
        ]
    heuristic = detect_heuristic_stages(heuristic_features)
    probabilities = sequence_probabilities(model, seqs, k, len(stages))
    benign = stages.index("benign") if "benign" in stages else 0
    attack = 1.0 - probabilities[:, :, benign]
    window_ms = 60_000
    last_window = int(windows.max())
    by_window: dict[int, list[int]] = {}
    for index, window in enumerate(windows):
        by_window.setdefault(int(window), []).append(index)

    timeline = []
    observed_peak = 0.0
    for window in sorted(by_window):
        rows = by_window[window]
        scores = attack[rows, 0]
        winner = rows[int(np.argmax(scores))]
        score = float(scores.max())
        observed_peak = max(observed_peak, score)
        stage = stages[int(np.argmax(probabilities[winner, 0]))]
        timeline.append({
            "t": _window_time(window, window_ms),
            "observed": True,
            "prob": round(float(probabilities[winner, 0].max()), 3),
            "attack_prob": round(score, 3),
            **describe(stage),
            "heuristic_stages": heuristic["timeline"].get(int(window), []),
        })

    future_rows = by_window.get(last_window, [])
    future_peak = 0.0
    for step in range(1, k + 1):
        if not future_rows:
            score = 0.0
            stage = "benign"
            prob = 0.0
        else:
            scores = attack[future_rows, step]
            winner = future_rows[int(np.argmax(scores))]
            score = float(scores.max())
            stage = stages[int(np.argmax(probabilities[winner, step]))]
            prob = float(probabilities[winner, step].max())
        future_peak = max(future_peak, score)
        timeline.append({
            "t": _window_time(last_window + step, window_ms),
            "observed": False,
            "prob": round(prob, 3),
            "attack_prob": round(score, 3),
            **describe(stage),
            "heuristic_stages": [],
        })

    flagged = []
    for index in by_window.get(last_window, []):
        future_scores = attack[index, 1:]
        if len(future_scores) == 0:
            continue
        peak_step = int(np.argmax(future_scores)) + 1
        peak = float(future_scores[peak_step - 1])
        if peak <= 0.5:
            continue
        host = int(hosts[index])
        stage_name = _attack_stage(probabilities[index, 1], stages)
        per_step = [
            {
                "t": _window_time(int(windows[index]) + step, window_ms),
                "attack_prob": round(float(attack[index, step]), 3),
            }
            for step in range(0, k + 1)
        ]
        flagged.append(_host_card(
            host, peak, stage_name, model, seqs[index], features, stages, 1, k,
            per_step, flows, port_counts, int(windows[index]), "forecast_step_1",
        ))
    flagged = _trim_hosts(flagged)

    recent = sorted(by_window)[-CURRENT_OBSERVED_WINDOWS:]
    by_host: dict[int, list[int]] = {}
    for window in recent:
        for index in by_window[window]:
            by_host.setdefault(int(hosts[index]), []).append(index)
    current = []
    for host, indexes in by_host.items():
        indexes = sorted(indexes, key=lambda index: int(windows[index]))
        scores = [float(attack[index, 0]) for index in indexes]
        peak_offset = int(np.argmax(scores))
        peak = scores[peak_offset]
        if peak <= 0.5:
            continue
        peak_index = indexes[peak_offset]
        names = [stages[int(np.argmax(probabilities[index, 0]))] for index in indexes]
        peak_stage = stages[int(np.argmax(probabilities[peak_index, 0]))]
        stage_name = _mode_stage(names, peak_stage)
        per_step = [
            {
                "t": _window_time(int(windows[index]), window_ms),
                "attack_prob": round(float(attack[index, 0]), 3),
            }
            for index in indexes
        ]
        current.append(_host_card(
            host, peak, stage_name, model, seqs[peak_index], features, stages, 0, k,
            per_step, flows, port_counts, int(windows[peak_index]), "observed_window",
        ))
    current = _trim_hosts(current)

    heuristic_by_host = defaultdict(list)
    for hit in heuristic["hosts"]:
        heuristic_by_host[hit["host"]].append(hit)
    for card in flagged + current:
        card["heuristic_stages"] = heuristic_by_host.get(card["host"], [])

    explanation_host = flagged[0]["host"] if flagged else None
    explanation = flagged[0]["explanation"] if flagged else []
    stage_summary = _stage_summary(kept, flagged, stages)
    notes = [
        f"Host forecast uses {HOST_LSTM_NAME}, seed 0.",
        "Reconnaissance and exfiltration are separate heuristic signals, not learned LSTM stages or benchmark metrics.",
        "flag_basis is future: hosts and overall_risk use attack probability on the steps after the last observed window.",
        "current_hosts are hosts above 0.5 in any of the last 3 observed windows. That list is not the forecast.",
        NETWORK_RISK_DEFINITION,
        "flows_in_flagged_window lists up to five flows from the window that produced the host peak. They are not per-flow detections.",
    ]
    if replay:
        notes.append(REPLAY_NOTE)
    future = [entry for entry in timeline if not entry["observed"]]
    return {
        "model": HOST_MODE,
        "horizon_k": int(k),
        "windows": int(len(by_window)),
        "overall_risk": round(future_peak, 3),
        "observed_attack_probability": round(observed_peak, 3) if timeline else None,
        "timeline": timeline,
        "explanation": explanation,
        "explanation_host": explanation_host,
        "explanation_source": "forecast_step_1" if explanation else None,
        **stage_summary,
        "method": "gradient_x_input_logodds",
        "flagged_windows": [],
        "next_action": next((entry["action"] for entry in future if entry.get("action")), None),
        "supported_stages": list(stages),
        "not_predicted_stages": list(NOT_PREDICTED),
        "heuristic_stage_names": list(HEURISTIC_STAGES),
        "mitre": list(MITRE_TABLE),
        "hosts": flagged,
        "current_hosts": current,
        "flag_basis": FLAG_BASIS,
        "network_risk_definition": NETWORK_RISK_DEFINITION,
        "notes": notes,
        "heuristic_hosts": heuristic["hosts"],
        "heuristic_timeline": {str(window): hits for window, hits in heuristic["timeline"].items()},
    }


def forecast_host_file(path: Path, k: int = ROLLOUT_K, replay: bool = False) -> dict:
    table, meta, flows = aggregate_host_windows(path, window_s=60, keep_flows=True)
    counts = {int(port): int(count) for port, count in (meta.get("dst_port_counts") or {}).items()}
    body = forecast_host_frame(table, flows, counts, k=k, replay=replay)
    body.setdefault("notes", []).append(
        f"PCAP/CSV host-windows dropped by the min_flows=3 filter: {meta.get('min_flows_dropped_host_windows', 0)}."
    )
    return body
