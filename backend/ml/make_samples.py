"""Write label-chosen NetFlow-V3 test slices. Model scores are not used to pick them.

    python -m ml.make_samples --csv PATH
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from .host_forecast import REPLAY_NOTE, forecast_host_file, forecast_host_frame
from .host_v3 import PASS2_COLS, aggregate_host_windows, ipv4_from_uint32, load_host_table, network_split_map
from .netflow_v3 import _num, attack_bucket

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"
WINDOW_MS = 60_000
BEFORE = 10
AFTER = 5
MIN_WINDOWS = BEFORE + 1 + AFTER
TOTAL_BYTE_LIMIT = 40 * 1024 * 1024
INFILTRATION_BYTE_LIMIT = 12 * 1024 * 1024
ATTACK_STAGES = ("initial_access", "lateral_movement", "command_and_control")
SAMPLE_LABELS = {
    "brute_force": "initial_access",
    "infiltration": "lateral_movement",
    "bot": "command_and_control",
    "benign": "benign",
}
ATTACKS = (
    ("brute_force", "initial_access"),
    ("infiltration", "lateral_movement"),
    ("bot", "command_and_control"),
)


def _test_windows(csv_path: Path) -> set[int]:
    mapped = network_split_map(csv_path, window_s=60)
    return {int(window) for window, split in mapped.items() if split == "test"}


def _count_test_windows(csv_path: Path, test_windows: set[int]) -> tuple[dict[int, dict[str, int]], dict[int, int]]:
    """Per-window attack counts, and how many hosts in that window have at least 3 flows."""
    stats: dict[int, dict[str, int]] = {}
    rows = 0
    test_arr = np.asarray(sorted(test_windows), dtype=np.int64)
    host_parts = []
    for index, chunk in enumerate(pd.read_csv(
        csv_path, usecols=["FLOW_START_MILLISECONDS", "IPV4_SRC_ADDR", "Attack"], chunksize=1_000_000,
    )):
        ts = _num(chunk["FLOW_START_MILLISECONDS"]).astype(np.int64)
        window = (ts // WINDOW_MS).astype(np.int64)
        buckets = chunk["Attack"].map(attack_bucket).to_numpy()
        if len(test_arr) == 0:
            mask = np.zeros(len(window), dtype=bool)
        else:
            index_of = np.searchsorted(test_arr, window)
            index_of = np.clip(index_of, 0, len(test_arr) - 1)
            mask = test_arr[index_of] == window
        rows += len(chunk)
        print(f"sample scan chunk {index} rows {rows} test_rows {int(mask.sum())}", flush=True)
        if not mask.any():
            continue
        frame = pd.DataFrame({
            "window": window[mask],
            "src": chunk.loc[mask, "IPV4_SRC_ADDR"].astype(str).to_numpy(),
            "bucket": buckets[mask],
        })
        grouped = frame.groupby(["window", "bucket"], sort=False).size()
        for (slot, bucket), count in grouped.items():
            slot_counts = stats.setdefault(int(slot), {})
            slot_counts[str(bucket)] = slot_counts.get(str(bucket), 0) + int(count)
        host_parts.append(frame.groupby(["window", "src"], sort=False).size())
        if len(host_parts) >= 4:
            host_parts = [pd.concat(host_parts).groupby(level=[0, 1], sort=False).sum()]
        del chunk, frame
    eligible: dict[int, int] = {}
    if host_parts:
        hosts = pd.concat(host_parts).groupby(level=[0, 1], sort=False).sum()
        big = hosts[hosts >= 3]
        if len(big):
            eligible = {int(window): int(count) for window, count in big.groupby(level=0).size().items()}
    return stats, eligible


def _flows(stats: dict[int, dict[str, int]], window: int) -> int:
    return int(sum(stats.get(int(window), {}).values()))


def _ranked_lateral_spans(csv_path: Path) -> list[tuple[int, list[int]]]:
    """16-window test spans ranked by labelled lateral_movement host rows. Labels only."""
    frame, _meta = load_host_table(csv_path)
    test_windows = _test_windows(csv_path)
    lateral = frame.loc[frame["stage"] == "lateral_movement"].copy()
    lateral["window"] = lateral["window"].astype(int)
    counts = {int(window): int(count) for window, count in lateral.groupby("window").size().items()}
    ranked = []
    for center in counts:
        span = list(range(int(center) - BEFORE, int(center) + AFTER + 1))
        if len(span) < MIN_WINDOWS or not all(slot in test_windows for slot in span):
            continue
        total = sum(counts.get(slot, 0) for slot in span)
        ranked.append((total, span))
    ranked.sort(key=lambda item: (-item[0], item[1][0]))
    if not ranked:
        raise RuntimeError("No 16-window test span contains a labelled lateral_movement host row.")
    return ranked


def _attack_span(stats: dict[int, dict[str, int]], test_windows: set[int], bucket: str, eligible: dict[int, int]) -> list[int]:
    best = None
    for center in sorted(test_windows):
        if stats.get(center, {}).get(bucket, 0) <= 0:
            continue
        span = list(range(center - BEFORE, center + AFTER + 1))
        if len(span) < MIN_WINDOWS or not all(slot in test_windows for slot in span):
            continue
        if sum(eligible.get(slot, 0) for slot in span) < 1:
            continue
        weight = sum(_flows(stats, slot) for slot in span)
        if best is None or weight < best[0]:
            best = (weight, span)
    if best is None:
        raise RuntimeError(f"No test span of {MIN_WINDOWS} windows contains {bucket}.")
    return best[1]


def _benign_span(stats: dict[int, dict[str, int]], test_windows: set[int], eligible: dict[int, int]) -> list[int]:
    attack_keys = ("initial_access", "lateral_movement", "command_and_control", "excluded", "other")
    best = None
    for start in sorted(test_windows):
        span = list(range(start, start + MIN_WINDOWS))
        if not all(slot in test_windows for slot in span):
            continue
        counts = [stats.get(slot, {}) for slot in span]
        if any(sum(item.get(key, 0) for key in attack_keys) > 0 for item in counts):
            continue
        if any(eligible.get(slot, 0) < 1 for slot in span):
            continue
        weight = sum(_flows(stats, slot) for slot in span)
        if best is None or weight < best[0]:
            best = (weight, span)
    if best is None:
        raise RuntimeError(f"No benign-only test span of {MIN_WINDOWS} windows.")
    return best[1]


def _extract(csv_path: Path, spans: dict[str, list[int]]) -> dict[str, pd.DataFrame]:
    arrays = {name: np.asarray(span, dtype=np.int64) for name, span in spans.items()}
    parts = {name: [] for name in spans}
    rows = 0
    for index, chunk in enumerate(pd.read_csv(csv_path, chunksize=500_000)):
        ts = _num(chunk["FLOW_START_MILLISECONDS"]).astype(np.int64)
        window = (ts // WINDOW_MS).astype(np.int64)
        rows += len(chunk)
        print(f"sample extract chunk {index} rows {rows}", flush=True)
        for name, wanted in arrays.items():
            mask = np.isin(window, wanted)
            if mask.any():
                parts[name].append(chunk.loc[mask].copy())
        del chunk
    frames = {}
    for name, pieces in parts.items():
        frames[name] = pd.concat(pieces, ignore_index=True) if pieces else pd.DataFrame(columns=PASS2_COLS)
    return frames


def _shift_after(previous_end: int, frame: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    out = frame.copy()
    start = int(_num(out["FLOW_START_MILLISECONDS"]).min())
    target = (int(previous_end) // WINDOW_MS + 1) * WINDOW_MS
    delta = int(target - (start // WINDOW_MS) * WINDOW_MS)
    out["FLOW_START_MILLISECONDS"] = _num(out["FLOW_START_MILLISECONDS"]).astype(np.int64) + delta
    return out, delta


def _write_gz(frame: pd.DataFrame, path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False, compression="gzip")
    return path.stat().st_size


def write_samples(csv_path: Path, out_dir: Path = SAMPLES_DIR) -> dict[str, Path]:
    csv_path = Path(csv_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    test_windows = _test_windows(csv_path)
    print(f"test windows {len(test_windows)}", flush=True)
    stats, eligible = _count_test_windows(csv_path, test_windows)
    spans = {
        name: _attack_span(stats, test_windows, bucket, eligible)
        for name, bucket in ATTACKS
        if name != "infiltration"
    }
    spans["infiltration"] = _ranked_lateral_spans(csv_path)[0][1]
    spans["benign"] = _benign_span(stats, test_windows, eligible)
    for name, span in spans.items():
        print(f"span {name} windows {len(span)} {span[0]}..{span[-1]} flows {sum(_flows(stats, slot) for slot in span)}", flush=True)
    frames = _extract(csv_path, spans)
    written = {}
    for name in ("brute_force", "infiltration", "bot", "benign"):
        path = out_dir / f"{name}.csv.gz"
        size = _write_gz(frames[name], path)
        written[name] = path
        print(f"wrote {path} bytes {size} rows {len(frames[name])}", flush=True)

    replay_parts = []
    manifest_parts = []
    brute = frames["brute_force"].copy()
    replay_parts.append(brute)
    manifest_parts.append({
        "label": "brute_force",
        "windows": spans["brute_force"],
        "shift_ms": 0,
        "rows": int(len(brute)),
    })
    cursor = int(_num(brute["FLOW_START_MILLISECONDS"]).max())
    for name in ("infiltration", "bot"):
        shifted, delta = _shift_after(cursor, frames[name])
        replay_parts.append(shifted)
        manifest_parts.append({
            "label": name,
            "windows": spans[name],
            "shift_ms": int(delta),
            "rows": int(len(shifted)),
        })
        cursor = int(_num(shifted["FLOW_START_MILLISECONDS"]).max())
    replay = pd.concat(replay_parts, ignore_index=True)
    replay_path = out_dir / "kill_chain_replay.csv.gz"
    replay_size = _write_gz(replay, replay_path)
    written["kill_chain_replay"] = replay_path
    manifest = {
        "note": REPLAY_NOTE,
        "parts": manifest_parts,
    }
    manifest_path = out_dir / "replay_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    readme = out_dir / "README.md"
    readme.write_text(
        "\n".join([
            "# Forecast samples",
            "",
            "These NetFlow-V3 slices were chosen by label from the test split only.",
            "Model output was not used to pick the windows.",
            "",
            "Each attack slice keeps at least 10 context windows before the labeled window and 5 after it.",
            "The infiltration slice is the 16-window test span with the most labelled lateral_movement host rows.",
            "The benign slice is 16 test windows that contain no attack label.",
            "Every flow in those windows is kept, for every host.",
            "",
            "`kill_chain_replay.csv.gz` stitches the real test slices for brute force, infiltration, and bot",
            "by shifting FLOW_START_MILLISECONDS so the slices follow each other.",
            REPLAY_NOTE + ".",
            "",
        ]),
        encoding="utf-8",
    )
    total = sum(path.stat().st_size for path in written.values()) + manifest_path.stat().st_size + readme.stat().st_size
    print(f"sample bytes {total} replay {replay_size}", flush=True)
    if total > TOTAL_BYTE_LIMIT:
        raise RuntimeError(f"Samples are {total} bytes, above the {TOTAL_BYTE_LIMIT} byte cap.")
    return written


def _clock(window: int) -> str:
    return pd.Timestamp(int(window) * WINDOW_MS, unit="ms", tz="UTC").isoformat()


def _slice_facts(frame: pd.DataFrame, span: list[int], host_rows: int) -> dict:
    buckets = frame["Attack"].map(attack_bucket)
    attack = frame.loc[buckets == "lateral_movement"]
    start = int(_num(frame["FLOW_START_MILLISECONDS"]).min()) if len(frame) else int(span[0]) * WINDOW_MS
    end = int(_num(frame["FLOW_START_MILLISECONDS"]).max()) if len(frame) else int(span[-1]) * WINDOW_MS + WINDOW_MS
    attackers = sorted(attack["IPV4_SRC_ADDR"].astype(str).unique()) if len(attack) else []
    return {
        "windows": [int(window) for window in span],
        "time_start": pd.Timestamp(start, unit="ms", tz="UTC").isoformat(),
        "time_end": pd.Timestamp(end, unit="ms", tz="UTC").isoformat(),
        "window_start": _clock(span[0]),
        "window_end": _clock(span[-1]),
        "lateral_host_rows": int(host_rows),
        "attack_flows": int(len(attack)),
        "attacker_hosts": attackers,
    }


def rebuild_infiltration(csv_path: Path, out_dir: Path = SAMPLES_DIR) -> dict:
    """Replace infiltration.csv.gz and rebuild kill_chain_replay from the three slices."""
    csv_path = Path(csv_path)
    out_dir = Path(out_dir)
    ranked = _ranked_lateral_spans(csv_path)
    print(f"lateral spans {len(ranked)} best host_rows {ranked[0][0]}", flush=True)
    kept = None
    for host_rows, span in ranked:
        frame = _extract(csv_path, {"infiltration": span})["infiltration"]
        path = out_dir / "infiltration.csv.gz"
        size = _write_gz(frame, path)
        facts = _slice_facts(frame, span, host_rows)
        print(
            f"infiltration windows {span[0]}..{span[-1]} {_clock(span[0])} .. {_clock(span[-1])} "
            f"flows {facts['time_start']} .. {facts['time_end']} "
            f"lateral_host_rows {host_rows} attack_flows {facts['attack_flows']} "
            f"attacker_hosts {len(facts['attacker_hosts'])} bytes {size}",
            flush=True,
        )
        if size < INFILTRATION_BYTE_LIMIT:
            kept = {"path": path, "frame": frame, "span": span, "facts": facts, "bytes": size}
            break
        path.unlink(missing_ok=True)
        print("infiltration sample is over 12 MB; trying the next span", flush=True)
    if kept is None:
        raise RuntimeError("No lateral_movement test span stayed under 12 MB.")
    _rewrite_replay(out_dir, kept["frame"], kept["span"])
    return kept


def _rewrite_replay(out_dir: Path, infiltration: pd.DataFrame, span: list[int]) -> None:
    brute = pd.read_csv(out_dir / "brute_force.csv.gz")
    bot = pd.read_csv(out_dir / "bot.csv.gz")
    manifest_path = out_dir / "replay_manifest.json"
    previous = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {"parts": []}
    previous_parts = {part["label"]: part for part in previous.get("parts", [])}
    replay_parts = [brute]
    manifest_parts = [{
        "label": "brute_force",
        "windows": previous_parts.get("brute_force", {}).get("windows", []),
        "shift_ms": 0,
        "rows": int(len(brute)),
    }]
    cursor = int(_num(brute["FLOW_START_MILLISECONDS"]).max())
    for name, frame, windows in (
        ("infiltration", infiltration, [int(window) for window in span]),
        ("bot", bot, previous_parts.get("bot", {}).get("windows", [])),
    ):
        shifted, delta = _shift_after(cursor, frame)
        replay_parts.append(shifted)
        manifest_parts.append({
            "label": name,
            "windows": windows,
            "shift_ms": int(delta),
            "rows": int(len(shifted)),
        })
        cursor = int(_num(shifted["FLOW_START_MILLISECONDS"]).max())
    replay = pd.concat(replay_parts, ignore_index=True)
    replay_path = out_dir / "kill_chain_replay.csv.gz"
    size = _write_gz(replay, replay_path)
    manifest_path.write_text(json.dumps({"note": REPLAY_NOTE, "parts": manifest_parts}, indent=2), encoding="utf-8")
    print(f"wrote {replay_path} bytes {size} rows {len(replay)}", flush=True)


def _labelled_attackers(table: pd.DataFrame) -> list[dict]:
    rows = table.loc[table["stage"].isin(ATTACK_STAGES)].copy()
    found = []
    if len(rows) == 0:
        return found
    rows["src"] = rows["src"].astype(np.uint32)
    for src, group in rows.groupby("src", sort=False):
        counts = group["stage"].value_counts()
        stages = {str(name): int(count) for name, count in counts.items()}
        primary = str(counts.index[0])
        found.append({
            "host": ipv4_from_uint32(int(src)),
            "stage": primary,
            "host_rows": int(counts.sum()),
            "other_stages": [name for name in stages if name != primary],
        })
    found.sort(key=lambda item: item["host"])
    return found


def _ratio(numerator: int, denominator: int):
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _set_verdict(detected: list[dict], labelled: list[dict], label_stage: str | None) -> dict:
    labelled_by_host = {row["host"]: row for row in labelled}
    flagged = []
    mismatches = []
    for host in detected:
        label = labelled_by_host.get(host["host"])
        predicted = host["stage"]
        host_label = label["stage"] if label else None
        stage_matched = host_label is not None and predicted == host_label
        row = {
            "host": host["host"],
            "predicted_stage": predicted,
            "peak_attack_prob": host["peak_attack_prob"],
            "label_stage": host_label,
            "stage_matched": stage_matched,
        }
        flagged.append(row)
        if host_label is not None and not stage_matched:
            mismatches.append(row)
    flagged_hosts = {row["host"] for row in flagged}
    misses = [row for row in labelled if row["host"] not in flagged_hosts]
    hits = sum(1 for row in flagged if row["stage_matched"])
    predicted_stages = sorted({row["predicted_stage"] for row in flagged}) or ["benign"]
    return {
        "flagged_hosts": flagged,
        "missed_attackers": misses,
        "stage_mismatches": mismatches,
        "host_precision": _ratio(hits, len(flagged)),
        "host_recall": _ratio(len(labelled) - len(misses), len(labelled)),
        "predicted_stages": predicted_stages,
        "stage_matched": sum(1 for row in flagged if row["stage_matched"]),
        "stage_total": len(labelled),
        "flagged_unlabelled": sum(1 for row in flagged if row["label_stage"] is None),
    }


def _print_rate(value) -> str:
    return "undefined" if value is None else str(value)


def _print_verdict(title: str, block: dict) -> None:
    print(
        f"  {title} precision {_print_rate(block['host_precision'])} "
        f"recall {_print_rate(block['host_recall'])} stage_matched {block['stage_matched']}/{block['stage_total']} "
        f"flagged {len(block['flagged_hosts'])} misses {len(block['missed_attackers'])} "
        f"mismatches {len(block['stage_mismatches'])} predicted {block['predicted_stages']}",
        flush=True,
    )
    for row in block["flagged_hosts"]:
        print(
            f"    flagged {row['host']} predicted {row['predicted_stage']} label {row['label_stage']} "
            f"stage_matched {row['stage_matched']} peak {row['peak_attack_prob']}",
            flush=True,
        )
    for row in block["missed_attackers"]:
        print(f"    miss {row['host']} stage {row['stage']}", flush=True)
    for row in block["stage_mismatches"]:
        print(
            f"    mismatch {row['host']} predicted {row['predicted_stage']} label {row['label_stage']}",
            flush=True,
        )


def write_ground_truth(out_dir: Path = SAMPLES_DIR) -> dict:
    """Score every sample. Current detection and the future forecast are recorded separately."""
    from .host_forecast import NETWORK_RISK_DEFINITION

    out_dir = Path(out_dir)
    samples = {}
    names = ("brute_force", "infiltration", "bot", "benign", "kill_chain_replay")
    for name in names:
        path = out_dir / f"{name}.csv.gz"
        table, meta, flows = aggregate_host_windows(path, window_s=60, keep_flows=True)
        counts = {int(port): int(count) for port, count in (meta.get("dst_port_counts") or {}).items()}
        body = forecast_host_frame(table, flows, counts, replay=name == "kill_chain_replay")
        labelled = _labelled_attackers(table)
        label_stage = SAMPLE_LABELS.get(name)
        current = _set_verdict(body.get("current_hosts") or [], labelled, label_stage)
        forecast = _set_verdict(body.get("hosts") or [], labelled, label_stage)
        record = {
            "file": path.name,
            "label_stage": label_stage,
            "labelled_attackers": labelled,
            "current": current,
            "forecast": forecast,
            "overall_risk": body["overall_risk"],
            "flag_basis": body["flag_basis"],
            "network_risk_definition": body["network_risk_definition"],
            "windows": body["windows"],
        }
        samples[path.name] = record
        print(f"sample {path.name}", flush=True)
        print(f"  label_stage {label_stage} labelled attackers {len(labelled)}", flush=True)
        for row in labelled:
            extra = f" also {', '.join(row['other_stages'])}" if row.get("other_stages") else ""
            print(f"    {row['host']} stage {row['stage']} host_rows {row['host_rows']}{extra}", flush=True)
        _print_verdict("current", current)
        _print_verdict("forecast", forecast)
    payload = {
        "horizon_k": 5,
        "flag_basis": "future",
        "network_risk_definition": NETWORK_RISK_DEFINITION,
        "samples": samples,
    }
    path = out_dir / "ground_truth.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"wrote {path}", flush=True)
    return payload


def score_samples(paths: dict[str, Path]) -> None:
    for name, path in paths.items():
        body = forecast_host_file(path, replay=name == "kill_chain_replay")
        future = [row["attack_prob"] for row in body["timeline"] if not row["observed"]]
        hosts = body.get("hosts") or []
        print(f"sample {path.name}", flush=True)
        print(f"windows {body['windows']}", flush=True)
        print(f"max future attack_prob {max(future) if future else 0}", flush=True)
        print(f"flagged hosts {len(hosts)}", flush=True)
        if name == "benign" and hosts:
            print(f"benign sample flagged {len(hosts)} hosts", flush=True)
        for host in hosts:
            print(
                f"  {host['host']} stage {host['stage']} mitre_tactic {host['mitre_tactic']} "
                f"peak {host['peak_attack_prob']}",
                flush=True,
            )
        if hosts:
            top = hosts[0].get("explanation") or []
            print("top 3 features", flush=True)
            for row in top[:3]:
                print(
                    f"  {row['name']} {row.get('group') or row.get('kind')} "
                    f"attribution {row.get('attribution')} timestep {row.get('timestep')}",
                    flush=True,
                )


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Write label-chosen NetFlow-V3 test samples.")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--out", default=str(SAMPLES_DIR))
    parser.add_argument("--rebuild-infiltration", action="store_true")
    args = parser.parse_args(argv)
    out_dir = Path(args.out)
    if args.rebuild_infiltration:
        rebuild_infiltration(Path(args.csv), out_dir)
        write_ground_truth(out_dir)
        return
    written = write_samples(Path(args.csv), out_dir)
    score_samples(written)
    write_ground_truth(out_dir)


if __name__ == "__main__":
    main()
