"""Identity diagnostic for the saved seed-0 host LSTM. Does not train.

False-positive rate is the share of benign-labelled test host rows whose
horizon-0 attack probability, 1 - P(benign), exceeds 0.5.

    python -m ml.diag_hosts
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .config import SEQ_LEN
from .host_forecast import _lookup, _scale, load_host_lstm, sequence_probabilities
from .host_train import stack_host
from .host_v3 import apply_network_split, host_anchors, ipv4_from_uint32, load_host_table, network_split_map

MODELS_DIR = Path(__file__).resolve().parent / "models"
ATTACK_STAGES = ("initial_access", "lateral_movement", "command_and_control")
THRESHOLD = 0.5
CHUNK = 2048


def _default_csv() -> Path:
    meta_path = Path(__file__).resolve().parent / "cache" / "host_v3_w60_v1.meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    return Path(meta["source"]["path"])


def _rate(false_positives: int, rows: int):
    if rows == 0:
        return None
    return false_positives / rows


def _over_3x(left, right):
    if left is None or right is None:
        return None
    if left == 0 and right == 0:
        return False
    if left == 0 or right == 0:
        return True
    return max(left, right) / min(left, right) > 3


def _ratio(left, right):
    if left is None or right is None:
        return None
    low, high = (left, right) if left <= right else (right, left)
    if low == 0:
        return None if high == 0 else None
    return high / low


def _group(mask: np.ndarray, positive: np.ndarray) -> dict:
    rows = int(mask.sum())
    false_positives = int((mask & positive).sum())
    return {
        "benign_rows": rows,
        "false_positives": false_positives,
        "fpr": _rate(false_positives, rows),
    }


def _subnet(src: int) -> str:
    octets = ipv4_from_uint32(int(src)).split(".")
    return ".".join(octets[:3]) + ".0/24"


def _score_benign(frame: pd.DataFrame, anchors: np.ndarray) -> np.ndarray:
    bundle = load_host_lstm()
    features = list(bundle["features"])
    stages = list(bundle["stages"])
    scaled = _scale(frame, features, bundle["clip_high"], bundle["scaler"])
    hosts = frame["src"].to_numpy(np.uint32)
    windows = frame["window"].to_numpy(np.int64)
    pos = _lookup(frame)
    benign = stages.index("benign")
    attack = np.empty(len(anchors), np.float64)
    for start in range(0, len(anchors), CHUNK):
        chunk = anchors[start:start + CHUNK]
        seqs, _nxt, _ys = stack_host(
            scaled, hosts, windows, np.zeros(len(frame), np.int64), chunk, pos, SEQ_LEN, 0,
        )
        probabilities = sequence_probabilities(bundle["model"], seqs, 0, len(stages))
        attack[start:start + len(chunk)] = 1.0 - probabilities[:, 0, benign]
        print(f"diag scored {start + len(chunk)} / {len(anchors)}", flush=True)
    return attack

def _near_attack_report(scored: pd.DataFrame, anchors: np.ndarray, stages: np.ndarray, positive: np.ndarray, seq_len: int) -> dict:
    """Compute false‑positive rates for benign‑labelled test rows split by distance (in windows) to the nearest attack‑labelled row of the same host.
    Returns a dict with bands '<=3', '4-30', '>30', and 'no_attack' containing the _group dicts.
    """
    # Test split rows only
    test_rows = scored[scored["split"] == "test"]
    # Map host to sorted attack windows within test split
    attack_mask = test_rows["stage"].isin(ATTACK_STAGES)
    attack_hosts = test_rows.loc[attack_mask, ["src", "window"]]
    attack_dict = {}
    for src, grp in attack_hosts.groupby("src"):
        attack_dict[int(src)] = np.sort(grp["window"].to_numpy(np.int64))
    # Identify benign test rows (anchors already filtered to test split)
    benign_idx = anchors[stages[anchors] == "benign"]
    distances = np.empty(len(benign_idx), dtype=object)
    for i, idx in enumerate(benign_idx):
        src = int(scored.at[idx, "src"])
        win = int(scored.at[idx, "window"])
        attacks = attack_dict.get(src)
        if attacks is None or len(attacks) == 0:
            distances[i] = None
        else:
            distances[i] = int(np.min(np.abs(attacks - win)))
    # Build masks for distance bands
    mask_le3 = np.array([d is not None and d <= 3 for d in distances], dtype=bool)
    mask_4_30 = np.array([d is not None and 4 <= d <= 30 for d in distances], dtype=bool)
    mask_gt30 = np.array([d is not None and d > 30 for d in distances], dtype=bool)
    mask_no = np.array([d is None for d in distances], dtype=bool)
    return {
        "<=3": _group(mask_le3, positive),
        "4-30": _group(mask_4_30, positive),
        ">30": _group(mask_gt30, positive),
        "no_attack": _group(mask_no, positive),
    }
def diagnose(csv_path: Path) -> dict:
    frame, _meta = load_host_table(csv_path)
    split_map = network_split_map(csv_path)
    ever = set(int(src) for src in frame.loc[frame["stage"].isin(ATTACK_STAGES), "src"].astype(np.uint32))
    scored = apply_network_split(frame, split_map)
    anchors = host_anchors(scored, split_map, SEQ_LEN, 0)["test"]
    stages = scored["stage"].to_numpy()
    benign_idx = anchors[stages[anchors] == "benign"]
    print(f"diag benign test rows {len(benign_idx)} ever_attack_hosts {len(ever)}", flush=True)
    attack = _score_benign(scored, benign_idx)
    positive = attack > THRESHOLD
    src = scored["src"].to_numpy(np.uint32)[benign_idx]
    volume = scored["n"].to_numpy(np.float64)[benign_idx]
    ever_mask = np.fromiter((int(value) in ever for value in src), dtype=bool, count=len(src))
    never_mask = ~ever_mask
    groups = {
        "ever_attack": _group(ever_mask, positive),
        "never_attack": _group(never_mask, positive),
    }
    groups["ratio_high_to_low"] = _ratio(groups["ever_attack"]["fpr"], groups["never_attack"]["fpr"])
    groups["differ_by_more_than_3x"] = _over_3x(groups["ever_attack"]["fpr"], groups["never_attack"]["fpr"])
    # Near‑attack distance analysis
    near_attack = _near_attack_report(scored, anchors, stages, positive, SEQ_LEN)
    groups["near_attack"] = near_attack

    subnets = []
    labels = np.asarray([_subnet(int(value)) for value in src], dtype=object)
    for subnet in sorted(set(labels.tolist())):
        mask = labels == subnet
        block = _group(mask, positive)
        block["subnet"] = subnet
        subnets.append(block)

    decile_id = pd.qcut(volume, 10, labels=False, duplicates="drop")
    decile_id = np.asarray(decile_id, dtype=int)
    deciles = []
    for decile in sorted(set(decile_id.tolist())):
        member = decile_id == decile
        ever_block = _group(member & ever_mask, positive)
        never_block = _group(member & never_mask, positive)
        band = volume[member]
        deciles.append({
            "decile": int(decile) + 1,
            "n_min": float(band.min()) if len(band) else None,
            "n_max": float(band.max()) if len(band) else None,
            "ever_attack": ever_block,
            "never_attack": never_block,
            "ratio_high_to_low": _ratio(ever_block["fpr"], never_block["fpr"]),
            "differ_by_more_than_3x": _over_3x(ever_block["fpr"], never_block["fpr"]),
        })

    weight = 0.0
    ever_sum = 0.0
    never_sum = 0.0
    for row in deciles:
        left = row["ever_attack"]["benign_rows"]
        right = row["never_attack"]["benign_rows"]
        if left == 0 or right == 0:
            continue
        share = float(min(left, right))
        weight += share
        ever_sum += row["ever_attack"]["fpr"] * share
        never_sum += row["never_attack"]["fpr"] * share
    matched_ever = ever_sum / weight if weight else None
    matched_never = never_sum / weight if weight else None
    matched = {
        "weight": weight,
        "ever_attack_fpr": matched_ever,
        "never_attack_fpr": matched_never,
        "ratio_high_to_low": _ratio(matched_ever, matched_never),
        "differ_by_more_than_3x": _over_3x(matched_ever, matched_never),
    }
    return {
        "model": "v3_host_lstm_seed0.pt",
        "seed": 0,
        "horizon": 0,
        "threshold": THRESHOLD,
        "positive": "attack_prob = 1 - P(benign) > 0.5 on a benign-labelled test host row",
        "anchors": "test-split anchors whose 10-window history stays inside the test split",
        "ever_attack": "host has any initial_access, lateral_movement, or command_and_control row anywhere in the dataset",
        "benign_test_rows": int(len(benign_idx)),
        "false_positives": int(positive.sum()),
        "groups": groups,
        "subnets": subnets,
        "deciles": deciles,
        "volume_matched": matched,
        "near_attack": near_attack,
    }


def _print_fpr(name: str, block: dict) -> None:
    fpr = block["fpr"]
    shown = "undefined" if fpr is None else f"{fpr:.4f}"
    print(f"{name} fpr {shown} false_positives {block['false_positives']} benign_rows {block['benign_rows']}", flush=True)


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Host identity false-positive diagnostic.")
    parser.add_argument("--csv", default=str(_default_csv()))
    parser.add_argument("--out", default=str(MODELS_DIR / "diag_hosts.json"))
    args = parser.parse_args(argv)
    report = diagnose(Path(args.csv))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {out}", flush=True)
    _print_fpr("ever_attack", report["groups"]["ever_attack"])
    _print_fpr("never_attack", report["groups"]["never_attack"])
    print(
        f"group ratio {report['groups']['ratio_high_to_low']} "
        f"differ_by_more_than_3x {report['groups']['differ_by_more_than_3x']}",
        flush=True,
    )
    matched = report["volume_matched"]
    print(
        f"volume_matched ever_attack_fpr {matched['ever_attack_fpr']} "
        f"never_attack_fpr {matched['never_attack_fpr']} "
        f"ratio {matched['ratio_high_to_low']} "
        f"differ_by_more_than_3x {matched['differ_by_more_than_3x']}",
        flush=True,
    )
    print(f"subnets {len(report['subnets'])} deciles {len(report['deciles'])}", flush=True)


if __name__ == "__main__":
    main()
