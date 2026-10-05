"""CIC-IDS-2018 window loader and a separate logistic-regression experiment.

The synthetic generator and baseline.joblib are left in place. CIC class names
are attack labels, not PREDICT-X stages and not MITRE tactics. LABEL_TO_STAGE
is a coarse proxy so the existing six-stage baseline can be trained.
"""
import csv
import json
import os
import re
import sys
import warnings
from collections import Counter
from datetime import date
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from .baseline import HORIZONS, MODELS_DIR, shifted, train
from .features import CIC_FEATURES, _ALIASES
from .stages import STAGES

CAPTURE_FILES = [
    "Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
    "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
    "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
    "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
]
WINDOW_S = 60
EPISODE_GAP_S = 120
REAL_BUNDLE = "baseline_cicids2018.joblib"
REAL_BENCHMARK = "benchmark_cicids2018.json"

# Keys are the stripped, lower-cased CIC Label values actually present in these exports.
# "Infilteration" is the dataset's spelling.
LABEL_TO_STAGE = {
    "benign": "benign",
    "ftp-bruteforce": "initial_access",
    "ssh-bruteforce": "initial_access",
    "infilteration": "lateral_movement",
    "bot": "command_and_control",
    "brute force -web": "initial_access",
    "brute force -xss": "initial_access",
    "sql injection": "initial_access",
}
STAGE_NOTES = {
    "benign": "CIC class Benign. This is the dataset's benign label, not a MITRE tactic.",
    "ftp-bruteforce": (
        "Proxy only. CIC name for FTP password guessing against an exposed service. "
        "The CSV does not assign a MITRE tactic. initial_access is the closest of the "
        "six PREDICT-X stages; credential access is not one of those stages."
    ),
    "ssh-bruteforce": (
        "Proxy only. CIC name for SSH password guessing. Same limitation as FTP-BruteForce."
    ),
    "infilteration": (
        "Proxy only. The files spell this class Infilteration. On 2018-02-28 and 2018-03-01 "
        "that one label covers the infiltration scenario and does not separate foothold, discovery, "
        "command-and-control, or exfiltration. lateral_movement is the closest single "
        "PREDICT-X stage for post-compromise internal activity, not a per-flow MITRE annotation."
    ),
    "bot": (
        "Proxy only. CIC name for the Friday botnet scenario. The CSV does not assign a MITRE tactic. "
        "command_and_control is the closest of the six PREDICT-X stages for an established bot "
        "talking to its controller, not a per-flow MITRE annotation."
    ),
    "brute force -web": (
        "Proxy only. CIC name for HTTP password guessing, including the 2018-02-22 and 2018-02-23 "
        "web-attack captures. The CSV does not assign a MITRE tactic. initial_access is the closest "
        "of the six PREDICT-X stages; credential access is not one of those stages."
    ),
    "brute force -xss": (
        "Proxy only. CIC name for cross-site scripting against a web application. The CSV does not "
        "assign a MITRE tactic. initial_access is the closest of the six PREDICT-X stages for an "
        "exploit aimed at the exposed application, not a per-flow MITRE annotation."
    ),
    "sql injection": (
        "Proxy only. CIC name for SQL injection against a web application. The CSV does not assign "
        "a MITRE tactic. initial_access is the closest of the six PREDICT-X stages for an application "
        "exploit, not a per-flow MITRE annotation."
    ),
}
UNASSIGNED_STAGES = ["reconnaissance", "exfiltration"]
REQUIRED = ["timestamp", "dst_port", "duration", "fwd_pkts", "bwd_pkts",
            "fwd_bytes", "bwd_bytes", "syn", "rst", "iatm", "label"]


def resolve_data_dir(explicit: Path | None = None) -> Path:
    """CLI --csv path, otherwise PREDICT_X_DATA_DIR. There is no built-in directory."""
    if explicit is not None and str(explicit).strip():
        return Path(explicit)
    env = os.environ.get("PREDICT_X_DATA_DIR")
    if env and env.strip():
        return Path(env)
    raise FileNotFoundError("Pass --csv PATH or set PREDICT_X_DATA_DIR.")


def capture_paths(data_dir: Path) -> list[Path]:
    """Capture files that exist. Missing names are skipped with a warning."""
    root = Path(data_dir)
    found = []
    missing = []
    for name in CAPTURE_FILES:
        path = root / name
        if path.is_file():
            found.append(path)
        else:
            missing.append(path)
            warnings.warn(f"Skipping missing CIC capture: {path}", UserWarning, stacklevel=2)
    if not found:
        joined = ", ".join(str(path) for path in missing)
        raise FileNotFoundError("CIC-IDS-2018 file not found: " + joined)
    return found


def _key(name: str) -> str:
    return " ".join(str(name).strip().lower().split())


def _alias_index() -> dict:
    found = {}
    for canon, names in _ALIASES.items():
        for name in names:
            found[_key(name)] = canon
    found["label"] = "label"
    return found


def map_stage(label: str) -> str:
    key = _key(label)
    if key not in LABEL_TO_STAGE:
        known = ", ".join(sorted(LABEL_TO_STAGE))
        raise ValueError(f"No PREDICT-X stage proxy for CIC label {label!r}. Known labels: {known}.")
    stage = LABEL_TO_STAGE[key]
    if stage not in STAGES:
        raise ValueError(f"Proxy stage {stage!r} is not in STAGES.")
    return stage


def missing_required_columns(header: list) -> list[str]:
    """CSV header names that the CIC loader requires and this file does not have."""
    index = _alias_index()
    present = set()
    for column in header:
        canon = index.get(_key(column))
        if canon is not None:
            present.add(canon)
    missing = []
    for name in REQUIRED:
        if name in present:
            continue
        aliases = _ALIASES.get(name, [name])
        missing.append(aliases[0] if name != "label" else "Label")
    return missing


def _header(path: Path) -> list:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return next(csv.reader(handle))


def _bind(header: list) -> dict:
    index = _alias_index()
    keyed = {_key(col): col for col in header}
    bound = {}
    for key, raw in keyed.items():
        canon = index.get(key)
        if canon is not None and canon not in bound:
            bound[canon] = raw
    missing = [name for name in REQUIRED if name not in bound]
    if missing:
        raise ValueError(f"Missing required columns {missing}. Header keys: {sorted(keyed)}.")
    return bound


def _clean_numeric(series: pd.Series) -> pd.Series:
    values = pd.to_numeric(series, errors="coerce")
    return values.replace([np.inf, -np.inf], np.nan).fillna(0.0)


def _optional_numeric(chunk: pd.DataFrame, keep, bound: dict, key: str) -> np.ndarray:
    if key not in bound:
        return np.zeros(int(np.asarray(keep).sum()), dtype=np.float64)
    return _clean_numeric(chunk.loc[keep, bound[key]]).to_numpy()


def _new_acc() -> dict:
    return {
        "n": 0,
        "duration": 0.0,
        "fwd_pkts": 0.0,
        "bwd_pkts": 0.0,
        "fwd_bytes": 0.0,
        "bwd_bytes": 0.0,
        "syn": 0,
        "rst": 0,
        "iat": 0.0,
        "init_fwd": 0.0,
        "init_bwd": 0.0,
        "init_fwd_n": 0,
        "init_bwd_n": 0,
        "psh": 0,
        "ack": 0,
        "fin": 0,
        "urg": 0,
        "iat_max": 0.0,
        "pkt_var": 0.0,
        "ports": set(),
        "src_ips": set(),
        "dst_ips": set(),
        "labels": Counter(),
    }


def _log_mean(total: float, n: int) -> float:
    value = np.log1p(total / n) if n else 0.0
    return float(value) if np.isfinite(value) else 0.0


def choose_attack_label(counts: Counter) -> str:
    """Prefer the most common non-benign CIC label so a short attack is not hidden by benign volume."""
    attacks = [(label, n) for label, n in counts.items() if _key(label) != "benign"]
    if attacks:
        attacks.sort(key=lambda item: (-item[1], item[0]))
        return attacks[0][0]
    for label in counts:
        if _key(label) == "benign":
            return label
    return "Benign"


def load_capture(path: Path, window_s: int = WINDOW_S, chunksize: int = 200_000) -> tuple:
    """Stream one CICFlowMeter CSV into per-window accumulators. Raw rows are not retained."""
    bound = _bind(_header(path))
    has_src = "src_ip" in bound
    has_dst = "dst_ip" in bound
    usecols = list(dict.fromkeys(bound.values()))
    windows = {}
    stats = {
        "file": path.name,
        "rows_read": 0,
        "rows_used": 0,
        "dropped_header": 0,
        "dropped_timestamp": 0,
        "flow_labels": Counter(),
        "source_ip_column": has_src,
        "destination_ip_column": has_dst,
    }
    reader = pd.read_csv(
        path,
        usecols=usecols,
        chunksize=chunksize,
        encoding="utf-8-sig",
        low_memory=False,
    )
    for chunk in reader:
        stats["rows_read"] += len(chunk)
        stamp = chunk[bound["timestamp"]].astype(str).str.strip()
        label = chunk[bound["label"]].astype(str).str.strip()
        parsed = pd.to_datetime(stamp, format="%d/%m/%Y %H:%M:%S", errors="coerce")
        header_row = stamp.str.lower().eq("timestamp") | label.map(_key).eq("label")
        bad_time = ~header_row & (parsed.isna() | parsed.dt.year.ne(2018))
        stats["dropped_header"] += int(header_row.sum())
        stats["dropped_timestamp"] += int(bad_time.sum())
        keep = ~header_row & ~bad_time
        if not keep.any():
            continue
        kept = pd.DataFrame({
            "win": parsed.loc[keep].dt.floor(f"{window_s}s").to_numpy(),
            "duration": _clean_numeric(chunk.loc[keep, bound["duration"]]).to_numpy(),
            "fwd_pkts": _clean_numeric(chunk.loc[keep, bound["fwd_pkts"]]).to_numpy(),
            "bwd_pkts": _clean_numeric(chunk.loc[keep, bound["bwd_pkts"]]).to_numpy(),
            "fwd_bytes": _clean_numeric(chunk.loc[keep, bound["fwd_bytes"]]).to_numpy(),
            "bwd_bytes": _clean_numeric(chunk.loc[keep, bound["bwd_bytes"]]).to_numpy(),
            "syn": _clean_numeric(chunk.loc[keep, bound["syn"]]).to_numpy(),
            "rst": _clean_numeric(chunk.loc[keep, bound["rst"]]).to_numpy(),
            "iat": _clean_numeric(chunk.loc[keep, bound["iatm"]]).to_numpy(),
            "init_fwd": _optional_numeric(chunk, keep, bound, "init_fwd_win"),
            "init_bwd": _optional_numeric(chunk, keep, bound, "init_bwd_win"),
            "psh": _optional_numeric(chunk, keep, bound, "psh"),
            "ack": _optional_numeric(chunk, keep, bound, "ack"),
            "fin": _optional_numeric(chunk, keep, bound, "fin"),
            "urg": _optional_numeric(chunk, keep, bound, "urg"),
            "iat_max": _optional_numeric(chunk, keep, bound, "iat_max"),
            "pkt_var": _optional_numeric(chunk, keep, bound, "pkt_len_var"),
            "port": _clean_numeric(chunk.loc[keep, bound["dst_port"]]).to_numpy(),
            "label": label.loc[keep].to_numpy(),
        })
        if has_src:
            kept["src_ip"] = chunk.loc[keep, bound["src_ip"]].astype(str).str.strip().to_numpy()
        if has_dst:
            kept["dst_ip"] = chunk.loc[keep, bound["dst_ip"]].astype(str).str.strip().to_numpy()
        stats["rows_used"] += len(kept)
        stats["flow_labels"].update(kept["label"].value_counts().to_dict())
        for win, group in kept.groupby("win", sort=False):
            acc = windows.setdefault(win, _new_acc())
            acc["n"] += len(group)
            acc["duration"] += float(group["duration"].sum())
            acc["fwd_pkts"] += float(group["fwd_pkts"].sum())
            acc["bwd_pkts"] += float(group["bwd_pkts"].sum())
            acc["fwd_bytes"] += float(group["fwd_bytes"].sum())
            acc["bwd_bytes"] += float(group["bwd_bytes"].sum())
            acc["syn"] += int((group["syn"] > 0).sum())
            acc["rst"] += int((group["rst"] > 0).sum())
            acc["iat"] += float(group["iat"].sum())
            # CICFlowMeter stores -1 when a flow has no TCP window value.
            fwd = group["init_fwd"].to_numpy()
            bwd = group["init_bwd"].to_numpy()
            fwd_ok = fwd != -1
            bwd_ok = bwd != -1
            acc["init_fwd"] += float(fwd[fwd_ok].sum()) if fwd_ok.any() else 0.0
            acc["init_bwd"] += float(bwd[bwd_ok].sum()) if bwd_ok.any() else 0.0
            acc["init_fwd_n"] += int(fwd_ok.sum())
            acc["init_bwd_n"] += int(bwd_ok.sum())
            acc["psh"] += int((group["psh"] > 0).sum())
            acc["ack"] += int((group["ack"] > 0).sum())
            acc["fin"] += int((group["fin"] > 0).sum())
            acc["urg"] += int((group["urg"] > 0).sum())
            acc["iat_max"] += float(group["iat_max"].sum())
            acc["pkt_var"] += float(group["pkt_var"].sum())
            ports = pd.unique(group["port"].to_numpy())
            acc["ports"].update(int(port) for port in ports if np.isfinite(port))
            acc["labels"].update(group["label"].value_counts().to_dict())
            if has_src:
                acc["src_ips"].update(group["src_ip"].unique())
            if has_dst:
                acc["dst_ips"].update(group["dst_ip"].unique())
    return windows, stats


def windows_to_frame(windows: dict, has_src: bool, has_dst: bool) -> pd.DataFrame:
    rows = []
    for win in sorted(windows):
        acc = windows[win]
        n = acc["n"]
        if n <= 0:
            continue
        attack_label = choose_attack_label(acc["labels"])
        row = {
            "window_start": win,
            "attack_label": attack_label,
            "stage": map_stage(attack_label),
            "n_flows": n,
            "log_mean_duration": _log_mean(acc["duration"], n),
            "mean_fwd_pkts": acc["fwd_pkts"] / n,
            "mean_bwd_pkts": acc["bwd_pkts"] / n,
            "log_mean_fwd_bytes": _log_mean(acc["fwd_bytes"], n),
            "log_mean_bwd_bytes": _log_mean(acc["bwd_bytes"], n),
            "syn_ratio": acc["syn"] / n,
            "rst_ratio": acc["rst"] / n,
            "uniq_dst_ports": len(acc["ports"]),
            "uniq_dst_ips": len(acc["dst_ips"]) if has_dst else 0,
            "uniq_src_ips": len(acc["src_ips"]) if has_src else 0,
            "log_mean_iat": _log_mean(acc["iat"], n),
            "mean_init_fwd_win_byts": acc["init_fwd"] / acc["init_fwd_n"] if acc["init_fwd_n"] else 0.0,
            "mean_init_bwd_win_byts": acc["init_bwd"] / acc["init_bwd_n"] if acc["init_bwd_n"] else 0.0,
            "psh_ratio": acc["psh"] / n,
            "ack_ratio": acc["ack"] / n,
            "fin_ratio": acc["fin"] / n,
            "urg_ratio": acc["urg"] / n,
            "log_mean_flow_iat_max": _log_mean(acc["iat_max"], n),
            "log_mean_pkt_len_var": _log_mean(acc["pkt_var"], n),
        }
        rows.append(row)
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise ValueError("No windows were produced from the CIC-IDS-2018 files.")
    return frame


def assign_episodes(frame: pd.DataFrame, gap_s: int = EPISODE_GAP_S) -> pd.DataFrame:
    """Split each day on time gaps. The earliest run is train; every later run is test.

    These two captures each pause for more than two minutes before the afternoon
    session, and the attack labels occur on both sides of that pause.
    """
    parts = []
    ordered = frame.sort_values("window_start")
    gap = pd.Timedelta(seconds=gap_s)
    for _, day in ordered.groupby(ordered["window_start"].dt.date, sort=True):
        day = day.sort_values("window_start")
        starts = day["window_start"].tolist()
        cuts = [0]
        for index in range(1, len(day)):
            if starts[index] - starts[index - 1] > gap:
                cuts.append(index)
        cuts.append(len(day))
        if len(cuts) < 3:
            raise RuntimeError(f"Capture day {starts[0].date()} has no time gap to hold out a future session.")
        for run_index, (left, right) in enumerate(zip(cuts, cuts[1:])):
            piece = day.iloc[left:right].copy()
            date = piece["window_start"].iloc[0].date().isoformat()
            role = "train" if run_index == 0 else "test"
            piece["split"] = role
            piece["episode_id"] = f"{date}-{role}" if run_index == 0 else f"{date}-test-r{run_index}"
            piece["window_idx"] = np.arange(len(piece))
            parts.append(piece)
    return pd.concat(parts, ignore_index=True)


def prepare_cicids(paths: list, window_s: int = WINDOW_S) -> tuple:
    windows = {}
    file_stats = []
    has_src = True
    has_dst = True
    for path in paths:
        part, stats = load_capture(Path(path), window_s=window_s)
        has_src = has_src and stats["source_ip_column"]
        has_dst = has_dst and stats["destination_ip_column"]
        file_stats.append(stats)
        for win, acc in part.items():
            dest = windows.setdefault(win, _new_acc())
            dest["n"] += acc["n"]
            for name in ("duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "iat",
                         "init_fwd", "init_bwd", "iat_max", "pkt_var"):
                dest[name] += acc[name]
            for name in ("syn", "rst", "psh", "ack", "fin", "urg", "init_fwd_n", "init_bwd_n"):
                dest[name] += acc[name]
            dest["ports"].update(acc["ports"])
            dest["src_ips"].update(acc["src_ips"])
            dest["dst_ips"].update(acc["dst_ips"])
            dest["labels"].update(acc["labels"])
    frame = assign_episodes(windows_to_frame(windows, has_src, has_dst))
    return frame, file_stats, {"source_ip_column": has_src, "destination_ip_column": has_dst}


def _file_date(name: str):
    match = re.search(r"(\d{2})-(\d{2})-(\d{4})", name)
    if match is None:
        return None
    day, month, year = (int(part) for part in match.groups())
    return date(year, month, day)


def print_load_table(frame: pd.DataFrame, file_stats: list) -> None:
    """file, rows used, label counts, and episode ids for the captures just loaded."""
    print("capture load")
    rows = []
    for stats in file_stats:
        day = _file_date(stats["file"])
        if day is None:
            episodes = "(none)"
        else:
            matched = frame.loc[frame["window_start"].dt.date == day, "episode_id"]
            episodes = ", ".join(dict.fromkeys(matched.tolist())) or "(none)"
        labels = ", ".join(
            f"{label}={int(count)}" for label, count in stats["flow_labels"].most_common()
        )
        rows.append({
            "file": stats["file"],
            "rows_used": int(stats["rows_used"]),
            "labels": labels,
            "episodes": episodes,
        })
    with pd.option_context("display.max_colwidth", None, "display.width", 200, "display.max_rows", None):
        print(pd.DataFrame(rows).to_string(index=False))


def _counts(frame: pd.DataFrame, column: str) -> dict:
    return {str(key): int(value) for key, value in frame[column].value_counts().items()}


def run_experiment(data_dir: Path, window_s: int = WINDOW_S) -> dict:
    paths = capture_paths(data_dir)
    frame, file_stats, availability = prepare_cicids(paths, window_s=window_s)
    print_load_table(frame, file_stats)
    columns = list(CIC_FEATURES)
    missing = [name for name in columns if name not in frame.columns]
    if missing:
        raise RuntimeError(f"Feature frame is missing CIC_FEATURES columns: {missing}.")
    train_df = frame[frame["split"] == "train"]
    test_df = frame[frame["split"] == "test"]
    if train_df.empty or test_df.empty:
        raise RuntimeError("Session split produced an empty train or test set.")
    bundle, bench = train(frame, test_episodes=test_df.episode_id.unique(), features=columns)
    pair_counts = []
    for horizon, row in zip(HORIZONS, bench):
        _, y_train = shifted(train_df, horizon, columns)
        _, y_test = shifted(test_df, horizon, columns)
        pair_counts.append({
            "horizon": horizon,
            "n_train_pairs": int(len(y_train)),
            "n_test_pairs": int(len(y_test)),
        })
        row["dataset"] = "CIC-IDS-2018"
        row["n_train_pairs"] = int(len(y_train))
        row["n_test_pairs"] = int(len(y_test))
    flow_labels = Counter()
    for stats in file_stats:
        flow_labels.update(stats["flow_labels"])
    report = {
        "dataset": "CIC-IDS-2018",
        "identifier": "real CIC-IDS-2018 CICFlowMeter results",
        "model": "logistic_regression",
        "files": [path.name for path in paths],
        "data_dir": str(data_dir),
        "copied_into_repository": False,
        "rows_read": int(sum(item["rows_read"] for item in file_stats)),
        "rows_used": int(sum(item["rows_used"] for item in file_stats)),
        "rows_dropped": int(sum(item["dropped_header"] + item["dropped_timestamp"] for item in file_stats)),
        "files_detail": [{
            "file": item["file"],
            "rows_read": int(item["rows_read"]),
            "rows_used": int(item["rows_used"]),
            "dropped_header": int(item["dropped_header"]),
            "dropped_timestamp": int(item["dropped_timestamp"]),
            "flow_labels": {str(k): int(v) for k, v in item["flow_labels"].items()},
        } for item in file_stats],
        "windows": int(len(frame)),
        "episodes": int(frame.episode_id.nunique()),
        "time_start": str(frame.window_start.min()),
        "time_end": str(frame.window_start.max()),
        "window_seconds": int(window_s),
        "attack_labels_flow": {str(k): int(v) for k, v in flow_labels.items()},
        "attack_labels_window": _counts(frame, "attack_label"),
        "stages_window": _counts(frame, "stage"),
        "label_to_stage": {
            label: {"stage": stage, "note": STAGE_NOTES[label]}
            for label, stage in LABEL_TO_STAGE.items()
        },
        "stages_not_assigned": UNASSIGNED_STAGES,
        "stage_mapping_disclaimer": (
            "CIC-IDS-2018 Label values are attack-class names. They are not MITRE ATT&CK "
            "tactics and they are not PREDICT-X stages. The mapping above is an explicit proxy."
        ),
        "window_label_rule": (
            "A window is labeled with its most frequent non-benign CIC label when any attack "
            "flow is present; otherwise Benign."
        ),
        "features": list(bundle["features"]),
        "unavailable_features": [],
        "split": {
            "method": "future session holdout inside each capture day",
            "gap_seconds": EPISODE_GAP_S,
            "rule": (
                f"Windows are {int(window_s)}s. Within each day, a gap longer than {EPISODE_GAP_S}s starts a new "
                "session. The earliest session is train. Later sessions are test. "
                "Horizon pairs stay inside one session, so a training window never predicts a test label. "
                "The logistic regression, horizons, scaler, and metrics are baseline.train."
            ),
            "train_time": [str(train_df.window_start.min()), str(train_df.window_start.max())],
            "test_time": [str(test_df.window_start.min()), str(test_df.window_start.max())],
            "n_train_episodes": int(train_df.episode_id.nunique()),
            "n_test_episodes": int(test_df.episode_id.nunique()),
            "train_stages": _counts(train_df, "stage"),
            "test_stages": _counts(test_df, "stage"),
            "pair_counts": pair_counts,
        },
        "results": bench,
        "synthetic_artifacts_unchanged": ["baseline.joblib", "benchmark.json"],
    }
    if not availability["source_ip_column"]:
        report["unavailable_features"].append({
            "feature": "uniq_src_ips",
            "reason": "Omitted from CIC_FEATURES. These CICFlowMeter ML CSVs have no source-IP column.",
        })
    if not availability["destination_ip_column"]:
        report["unavailable_features"].append({
            "feature": "uniq_dst_ips",
            "reason": "Omitted from CIC_FEATURES. These CICFlowMeter ML CSVs have no destination-IP column.",
        })
    MODELS_DIR.mkdir(exist_ok=True)
    bundle_path = MODELS_DIR / REAL_BUNDLE
    report_path = MODELS_DIR / REAL_BENCHMARK
    joblib.dump(bundle, bundle_path)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["wrote"] = [str(bundle_path), str(report_path)]
    return report


def _print_report(report: dict) -> None:
    print("rows_read", report["rows_read"])
    print("rows_used", report["rows_used"])
    print("rows_dropped", report["rows_dropped"])
    print("windows", report["windows"])
    print("episodes", report["episodes"])
    print("flow_labels", report["attack_labels_flow"])
    print("window_labels", report["attack_labels_window"])
    print("window_stages", report["stages_window"])
    print("train_episodes", report["split"]["n_train_episodes"],
          "test_episodes", report["split"]["n_test_episodes"])
    print("train_stages", report["split"]["train_stages"])
    print("test_stages", report["split"]["test_stages"])
    print(pd.DataFrame(report["results"]).to_string(index=False))
    for path in report["wrote"]:
        print("wrote", path)


if __name__ == "__main__":
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else resolve_data_dir()
    _print_report(run_experiment(directory))
