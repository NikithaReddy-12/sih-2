from __future__ import annotations

import ipaddress
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from ml.host_forecast import ipv4_from_uint32, load_host_lstm, sequence_probabilities, _lookup, _scale
from ml.host_train import stack_host
from ml.host_v3 import aggregate_host_windows

TARGET_HOST = "13.58.98.64"
TARGET_UINT = int(ipaddress.ip_address(TARGET_HOST))


def main() -> None:
    sample = ROOT / "backend" / "samples" / "brute_force.csv.gz"
    table, _meta, _flows = aggregate_host_windows(sample, window_s=60, keep_flows=True)
    kept = table.loc[table["stage"] != "dropped"].reset_index(drop=True) if "stage" in table.columns else table

    bundle = load_host_lstm()
    model = bundle["model"]
    features = list(bundle["features"])
    stages = list(bundle["stages"])
    scaled = _scale(kept, features, bundle["clip_high"], bundle["scaler"])
    hosts = kept["src"].to_numpy(np.uint32)
    windows = kept["window"].to_numpy(np.int64)
    pos = _lookup(kept)
    seqs, _nxt, _ys = stack_host(
        scaled,
        hosts,
        windows,
        np.zeros(len(kept), np.int64),
        np.arange(len(kept), dtype=np.int64),
        pos,
        10,
        3,
    )
    probabilities = sequence_probabilities(model, seqs, 3, len(stages))
    benign_index = stages.index("benign")
    attack = 1.0 - probabilities[:, :, benign_index]
    by_window: dict[int, list[int]] = defaultdict(list)
    for index, window in enumerate(windows):
        by_window[int(window)].append(index)

    print("time,network_attack_prob,top_host_ip,top_host_stage,top_host_attack_prob,target_host,target_stage,target_attack_prob")
    for window in sorted(by_window):
        rows = by_window[window]
        scores = attack[rows, 0]
        winner_index = rows[int(np.argmax(scores))]
        top_host = int(hosts[winner_index])
        top_ip = ipv4_from_uint32(top_host)
        top_stage = stages[int(np.argmax(probabilities[winner_index, 0]))]
        top_attack = float(scores.max())

        target_stage = "-"
        target_attack = None
        for idx in rows:
            if int(hosts[idx]) == TARGET_UINT:
                target_stage = stages[int(np.argmax(probabilities[idx, 0]))]
                target_attack = float(attack[idx, 0])
                break

        print(
            f"{pd.Timestamp(int(window) * 60_000, unit='ms', tz='UTC').isoformat()},"
            f"{top_attack:.3f},"
            f"{top_ip},{top_stage},{top_attack:.3f},"
            f"{TARGET_HOST if target_attack is not None else '-'},"
            f"{target_stage},"
            f"{target_attack:.3f}" if target_attack is not None else f"{TARGET_HOST if target_attack is not None else '-'},"
            )

    print("future_probabilities,0.063,0.019,0.017")


if __name__ == "__main__":
    main()
