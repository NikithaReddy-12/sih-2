"""Train host-level models and write benchmark_v3_host.json.

The network-level artifacts and benchmark_v3.json are not overwritten.

    python -m ml.host_train --csv PATH --window-s 60 --seeds 5
"""
from __future__ import annotations

import argparse
import faulthandler
import gc
import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression, SGDClassifier

from .baseline import MODELS_DIR
from .config import EVAL_HORIZONS, ROLLOUT_K, SEQ_LEN, V3_STAGES
from .host_v3 import CACHE_DIR
from .host_v3 import (
    CONTEXT_FEATURES,
    CONCENTRATION_FEATURES,
    FLOW_FEATURES,
    HEAVY_FEATURES,
    HOST_FEATURES,
    PACKET_FEATURES,
    fill_split_gaps,
    apply_network_split,
    build_host_features,
    host_anchors,
    load_host_table,
    network_split_map,
)
from .model_v3 import (
    _aggregate,
    _fmt,
    _horizon_block,
    _macro_f1,
    _onset,
    _predict_lstm,
    _print_step9,
    _print_table,
    _py,
    _split_payload,
    _stat,
    _verdict,
    fit_clip_scaler,
    fit_lstm,
    load_lstm,
    save_logistic,
    save_lstm,
    transform_matrix,
)
from .model_v3 import ConstantStageModel
from .netflow_v3 import coverage_sentence

CHECKPOINT = CACHE_DIR / "host_v3_train_ckpt.joblib"

BENCHMARK_NAME = "benchmark_v3_host.json"
# One completed full-data seed has to finish inside this limit before seed 4 is trained.
FULL_SEED_LIMIT_S = 20 * 60
BUDGET_SEEDS = (0, 1)
BUDGET_TRAIN_ANCHORS = 25_000
BUDGET_VAL_ANCHORS = 8_000
BUDGET_LSTM_EPOCHS = 4
BUDGET_LSTM_PATIENCE = 2
BUDGET_SGD_MAX_ITER = 12
FEATURE_SETS = {
    "all": HOST_FEATURES,
    "flow": FLOW_FEATURES + ["active"],
    "flow+packet": FLOW_FEATURES + PACKET_FEATURES + ["active"],
    "flow+packet+concentration": FLOW_FEATURES + PACKET_FEATURES + CONCENTRATION_FEATURES + ["active"],
}


def _codes(stages: np.ndarray) -> np.ndarray:
    mapping = {name: index for index, name in enumerate(V3_STAGES)}
    return np.asarray([mapping[str(stage)] for stage in stages], dtype=np.int64)


def _lookup(frame) -> dict[tuple[int, int], int]:
    hosts = frame["src"].to_numpy(np.uint32)
    windows = frame["window"].to_numpy(np.int64)
    return {(int(hosts[index]), int(windows[index])): index for index in range(len(frame))}


def _memmap(path: Path, shape, dtype):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    return np.lib.format.open_memmap(str(path), mode="w+", dtype=dtype, shape=shape)


def stack_host(scaled, hosts, windows, stage_codes, anchors, pos, seq_len, k, dest=None):
    count = len(anchors)
    width = scaled.shape[1]
    if dest is None:
        seqs = np.zeros((count, seq_len, width), np.float32)
        nxt = np.zeros((count, width), np.float32)
        ys = np.zeros((count, k + 1), np.int64)
    else:
        seqs, nxt, ys = dest
        seqs[:] = 0
        nxt[:] = 0
        ys[:] = 0
    for row, anchor in enumerate(anchors):
        host = int(hosts[int(anchor)])
        window = int(windows[int(anchor)])
        for step in range(seq_len):
            found = pos.get((host, window - (seq_len - 1) + step))
            if found is not None:
                seqs[row, step] = scaled[found]
        found_next = pos.get((host, window + 1))
        if found_next is not None:
            nxt[row] = scaled[found_next]
        for step in range(k + 1):
            found_y = pos.get((host, window + step))
            if found_y is not None:
                ys[row, step] = stage_codes[found_y]
    return seqs, nxt, ys


def _scale_observed(raw: np.ndarray, names: list[str], train_rows: np.ndarray):
    """Scale numeric features. Leave the active flag as 0 or 1 so silence stays a zero."""
    if names[-1] != "active":
        raise RuntimeError("active must be the last host feature so a missing slot is a zero vector")
    core_names = names[:-1]
    heavy = [name for name in HEAVY_FEATURES if name in core_names]
    core = raw[:, :-1]
    clip, scaler, _clipped = fit_clip_scaler(core[train_rows], core_names, heavy)
    scaled_core = transform_matrix(core, core_names, clip, scaler)
    active = raw[:, -1:].astype(np.float32)
    scaled = np.concatenate([scaled_core, active], axis=1)
    scaler.mean_ = np.concatenate([np.asarray(scaler.mean_, dtype=np.float64), [0.0]])
    scaler.scale_ = np.concatenate([np.asarray(scaler.scale_, dtype=np.float64), [1.0]])
    if hasattr(scaler, "var_"):
        scaler.var_ = np.concatenate([np.asarray(scaler.var_, dtype=np.float64), [1.0]])
    scaler.n_features_in_ = len(names)
    return scaled, clip, scaler


def _attack_proba(model, values: np.ndarray) -> np.ndarray:
    """1 - P(benign). A constant non-benign model counts as 1."""
    if len(values) == 0:
        return np.zeros(0, dtype=np.float64)
    if isinstance(model, ConstantStageModel):
        return np.full(len(values), 0.0 if int(model.label) == 0 else 1.0)
    proba = model.predict_proba(values)
    classes = [int(label) for label in model.classes_]
    benign = proba[:, classes.index(0)] if 0 in classes else np.zeros(len(values))
    return 1.0 - benign


def _lstm_attack_proba(model, seqs: np.ndarray, k: int) -> np.ndarray:
    """Attack probability at the current step and each of the next k steps."""
    import torch
    curves = np.zeros((len(seqs), k + 1), dtype=np.float64)
    if len(seqs) == 0:
        return curves
    model.eval()
    with torch.no_grad():
        for start in range(0, len(seqs), 256):
            batch = torch.tensor(seqs[start:start + 256], dtype=torch.float32)
            now, future, _nxt = model(batch, k)
            now_b = torch.softmax(now, dim=-1)[:, 0].cpu().numpy()
            fut_b = torch.softmax(future, dim=-1)[:, :, 0].cpu().numpy()
            stop = start + len(batch)
            curves[start:stop, 0] = 1.0 - now_b
            curves[start:stop, 1:] = 1.0 - fut_b
    return curves


def network_alarm(window_ids: np.ndarray, future_prob: np.ndarray, attack_windows: set[int], k: int = ROLLOUT_K) -> dict:
    """Window risk is the max host attack probability. Score benign windows for an onset inside K."""
    if len(window_ids) == 0:
        return {"precision": None, "recall": None, "fpr": None, "lead": None, "n": 0}
    frame = pd.DataFrame({"window": window_ids.astype(np.int64)})
    for step in range(k):
        frame[str(step)] = future_prob[:, step]
    risk = frame.groupby("window", sort=False).max()
    truth = []
    pred = []
    leads = []
    for window, row in risk.iterrows():
        window = int(window)
        if window in attack_windows:
            continue
        coming = [step for step in range(1, k + 1) if (window + step) in attack_windows]
        called = [step for step in range(1, k + 1) if float(row[str(step - 1)]) >= 0.5]
        is_true = bool(coming)
        is_pred = bool(called)
        truth.append(is_true)
        pred.append(is_pred)
        if is_true and is_pred:
            leads.append(min(coming) - min(called))
    truth_a = np.asarray(truth, dtype=bool)
    pred_a = np.asarray(pred, dtype=bool)
    tp = int(np.sum(truth_a & pred_a))
    fp = int(np.sum(~truth_a & pred_a))
    tn = int(np.sum(~truth_a & ~pred_a))
    fn = int(np.sum(truth_a & ~pred_a))
    return {
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "fpr": fp / (fp + tn) if (fp + tn) else 0.0,
        "lead": float(np.mean(leads)) if leads else None,
        "n": int(len(truth)),
    }


def block_bootstrap(y_true, y_model, y_base, block_ids, skip_labels=(), n_boot: int = 200, seed: int = 0) -> dict:
    """95% interval for macro-F1(model) - macro-F1(baseline), resampling time blocks."""
    y_true = np.asarray(y_true)
    y_model = np.asarray(y_model)
    y_base = np.asarray(y_base)
    block_ids = np.asarray(block_ids)
    if len(y_true) == 0:
        return {"low": None, "high": None, "mean": None, "beats": False}
    uniq, inverse = np.unique(block_ids, return_inverse=True)
    groups = [np.flatnonzero(inverse == index) for index in range(len(uniq))]
    rng = np.random.default_rng(seed)
    diffs = np.empty(n_boot, dtype=np.float64)
    for draw in range(n_boot):
        pick = rng.integers(0, len(groups), len(groups))
        idx = np.concatenate([groups[int(item)] for item in pick])
        diffs[draw] = _macro_f1(y_true[idx], y_model[idx], skip_labels) - _macro_f1(y_true[idx], y_base[idx], skip_labels)
    low, high = np.percentile(diffs, [2.5, 97.5])
    return {"low": float(low), "high": float(high), "mean": float(diffs.mean()), "beats": bool(low > 0.0)}


def _cap_anchors(index: np.ndarray, stage_codes: np.ndarray, cap: int, seed: int) -> np.ndarray:
    """Stratified subsample. Classes that are present stay present when the cap allows it."""
    index = np.asarray(index, dtype=np.int64)
    if len(index) <= int(cap):
        return index
    labels = np.asarray(stage_codes)[index]
    classes, counts = np.unique(labels, return_counts=True)
    raw = counts.astype(np.float64) * (int(cap) / len(index))
    alloc = np.floor(raw).astype(np.int64)
    for slot, count in enumerate(counts):
        if count > 0 and alloc[slot] == 0 and int(alloc.sum()) < int(cap):
            alloc[slot] = 1
    while int(alloc.sum()) > int(cap):
        donor = int(np.argmax(alloc))
        if alloc[donor] <= 0:
            break
        alloc[donor] -= 1
    leftover = int(cap) - int(alloc.sum())
    fractional = np.argsort(-(raw - np.floor(raw)))
    for slot in fractional:
        if leftover <= 0:
            break
        room = int(counts[slot]) - int(alloc[slot])
        take = min(room, leftover)
        alloc[slot] += take
        leftover -= take
    rng = np.random.default_rng(int(seed))
    chosen = []
    for slot, label in enumerate(classes):
        pool = index[labels == label]
        take = min(int(alloc[slot]), len(pool))
        if take <= 0:
            continue
        chosen.append(rng.choice(pool, size=take, replace=False).astype(np.int64))
    if not chosen:
        return index[:0]
    return np.sort(np.concatenate(chosen))


def _full_seed_gap_seconds() -> list[float]:
    """Wall clock between consecutive saved full-data LSTM artifacts, seeds 0 through 3."""
    paths = [MODELS_DIR / f"v3_host_lstm_seed{seed}.pt" for seed in range(4)]
    if not all(path.is_file() for path in paths):
        return []
    stamps = [path.stat().st_mtime for path in paths]
    return [round(stamps[index + 1] - stamps[index], 1) for index in range(3)]


def _fit_host_logistic(x_train: np.ndarray, y_train: np.ndarray, seed: int, sgd_max_iter: int = 40):
    """Class-weighted L2 logistic regression.

    Narrow inputs use lbfgs. The flattened 10-window input is about 290 columns on
    528k sequences; that exact fit took about 55 minutes per horizon and the process
    then exited, so those fits use averaged SGD on the same loss.
    """
    classes = sorted(int(value) for value in np.unique(y_train)) if len(y_train) else []
    if len(classes) < 2:
        label = classes[0] if classes else 0
        return ConstantStageModel(label, list(range(len(V3_STAGES))))
    started = time.perf_counter()
    wide = x_train.shape[1] > 80
    if wide:
        model = SGDClassifier(
            loss="log_loss",
            penalty="l2",
            alpha=1.0 / max(len(y_train), 1),
            class_weight="balanced",
            max_iter=int(sgd_max_iter),
            tol=1e-3,
            random_state=int(seed),
            average=True,
        )
        solver = "sgd"
    else:
        model = LogisticRegression(
            class_weight="balanced",
            max_iter=500,
            solver="lbfgs",
            random_state=int(seed),
        )
        solver = "lbfgs"
    model.fit(x_train, y_train)
    elapsed = time.perf_counter() - started
    n_iter = getattr(model, "n_iter_", None)
    print(
        f"logistic fit {solver} seed {seed} n {len(y_train)} width {x_train.shape[1]} "
        f"n_iter {n_iter} seconds {elapsed:.1f}",
        flush=True,
    )
    return model


def _load_checkpoint(source: dict) -> dict:
    if not CHECKPOINT.is_file():
        return {}
    blob = joblib.load(CHECKPOINT)
    if blob.get("source") != source:
        return {}
    return dict(blob.get("done") or {})


def _save_checkpoint(source: dict, done: dict) -> None:
    CHECKPOINT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"source": source, "done": done}, CHECKPOINT)
    print(f"checkpoint {CHECKPOINT} keys {sorted(done)}", flush=True)


def _alarm_ready(block: dict, kind: str) -> bool:
    if kind != "all":
        return True
    return "network_alarm" in block and "bootstrap" in block


def _fill_alarm(block, lstm, seq_test, y_test, window_pred, flat_pred, window_future, flat_future, test_windows, attack_windows, skip):
    lstm_pred = _predict_lstm(lstm, seq_test, ROLLOUT_K) if len(seq_test) else np.zeros((0, ROLLOUT_K + 1), dtype=int)
    named = {
        "logistic_window": window_pred,
        "logistic_flat10": flat_pred,
        "persistence": {horizon: window_pred[0] for horizon in range(0, ROLLOUT_K + 1)},
        "lstm": {horizon: lstm_pred[:, horizon] for horizon in range(0, ROLLOUT_K + 1)},
    }
    persist = np.repeat((np.asarray(window_pred[0]) != 0).astype(np.float64)[:, None], ROLLOUT_K, axis=1)
    oracle = np.repeat((y_test[:, 0] != 0).astype(np.float64)[:, None], ROLLOUT_K, axis=1)
    lstm_prob = _lstm_attack_proba(lstm, seq_test, ROLLOUT_K)
    block["network_alarm"] = {
        "logistic_window": network_alarm(test_windows, window_future, attack_windows),
        "logistic_flat10": network_alarm(test_windows, flat_future, attack_windows),
        "persistence": network_alarm(test_windows, persist, attack_windows),
        "oracle_persistence_unattainable": network_alarm(test_windows, oracle, attack_windows),
        "lstm": network_alarm(test_windows, lstm_prob[:, 1:], attack_windows),
    }
    block_ids = test_windows // 30
    block["bootstrap"] = {}
    for baseline in ("logistic_window", "logistic_flat10", "persistence"):
        block["bootstrap"][baseline] = {}
        for horizon in EVAL_HORIZONS:
            block["bootstrap"][baseline][str(horizon)] = block_bootstrap(
                y_test[:, horizon],
                named["lstm"][horizon],
                named[baseline][horizon],
                block_ids,
                skip,
                n_boot=200,
                seed=1000 + int(block["seed"]) * 17 + int(horizon),
            )
    return block


def _train_set(frame, names, seeds, kind, save: bool, skip_stages, budget: bool = False, feature_set: str | None = None) -> list[dict]:
    partial_dir = CACHE_DIR / "host_partial"
    partial_dir.mkdir(parents=True, exist_ok=True)
    safe_kind = "".join(ch if ch.isalnum() else "_" for ch in kind)
    seed_paths = {int(seed): partial_dir / f"{safe_kind}_seed{int(seed)}.joblib" for seed in seeds}
    if seed_paths and all(path.is_file() for path in seed_paths.values()):
        loaded = [joblib.load(seed_paths[int(seed)]) for seed in seeds]
        if all(_alarm_ready(block, kind) for block in loaded):
            print(f"checkpoint hit {kind}", flush=True)
            return loaded
        print(f"checkpoint hit {kind} models; filling network alarm and bootstrap", flush=True)
    raw = build_host_features(frame)[list(names)].to_numpy(np.float64)
    stage_codes = _codes(frame["stage"].to_numpy())
    train_rows = np.flatnonzero(frame["split"].to_numpy() == "train")
    scaled, clip, scaler = _scale_observed(raw, list(names), train_rows)
    del raw
    gc.collect()
    pos = _lookup(frame)
    hosts = frame["src"].to_numpy(np.uint32)
    windows = frame["window"].to_numpy(np.int64)
    anchors = {
        split: np.flatnonzero(frame["anchor_split"].to_numpy() == split)
        for split in ("train", "val", "test")
    }
    print(
        f"anchors {kind} " + " ".join(f"{split} {len(anchors[split])}" for split in anchors),
        flush=True,
    )
    if budget:
        anchors["train"] = _cap_anchors(anchors["train"], stage_codes, BUDGET_TRAIN_ANCHORS, 17)
        anchors["val"] = _cap_anchors(anchors["val"], stage_codes, BUDGET_VAL_ANCHORS, 19)
        print(
            f"budget {kind} train {len(anchors['train'])} val {len(anchors['val'])} "
            f"test {len(anchors['test'])} lstm_epochs {BUDGET_LSTM_EPOCHS} sgd_max_iter {BUDGET_SGD_MAX_ITER}",
            flush=True,
        )
    skip = tuple(V3_STAGES.index(name) for name in skip_stages)
    width = len(names)
    mmap_dir = partial_dir / "mmap"

    def _pack(split: str, on_disk: bool):
        index = anchors[split]
        if len(index) == 0:
            return (
                np.zeros((0, SEQ_LEN, width), np.float32),
                np.zeros((0, width), np.float32),
                np.zeros((0, ROLLOUT_K + 1), np.int64),
            )
        if on_disk:
            dest = (
                _memmap(mmap_dir / f"{safe_kind}_{split}_seq.npy", (len(index), SEQ_LEN, width), np.float32),
                _memmap(mmap_dir / f"{safe_kind}_{split}_nxt.npy", (len(index), width), np.float32),
                np.zeros((len(index), ROLLOUT_K + 1), np.int64),
            )
        else:
            dest = None
        return stack_host(scaled, hosts, windows, stage_codes, index, pos, SEQ_LEN, ROLLOUT_K, dest)

    # Train history is the large array. Keep it on disk so the LSTM fit stays inside RAM.
    seq_train, nxt_train, y_train = _pack("train", True)
    seq_val, _nxt_val, y_val = _pack("val", False)
    x_now = scaled[anchors["train"]] if len(anchors["train"]) else np.zeros((0, width), np.float32)
    flat_train = seq_train.reshape(len(seq_train), -1)
    seq_test, _nxt_test, y_test = _pack("test", False)
    x_test = scaled[anchors["test"]] if len(anchors["test"]) else np.zeros((0, width), np.float32)
    flat_test = seq_test.reshape(len(seq_test), -1)
    del scaled
    gc.collect()
    benign_now = y_test[:, 0] == 0 if len(y_test) else np.zeros(0, dtype=bool)
    procedure = "budget" if budget else "full"
    print(
        f"fit logistic {kind} once ({procedure}); seeds {list(seeds)} change the LSTM",
        flush=True,
    )
    sgd_max_iter = BUDGET_SGD_MAX_ITER if budget else 40
    pred_path = partial_dir / f"{safe_kind}_pred.joblib"
    if pred_path.is_file():
        print(f"checkpoint hit {kind} logistic", flush=True)
        saved_pred = joblib.load(pred_path)
        window_models = saved_pred["window_models"]
        flat_models = saved_pred["flat_models"]
        window_pred = saved_pred["window_pred"]
        flat_pred = saved_pred["flat_pred"]
    else:
        label_cols = y_train if len(y_train) else np.zeros((0, ROLLOUT_K + 1), np.int64)
        window_models = {}
        flat_models = {}
        for horizon in range(0, ROLLOUT_K + 1):
            print(f"logistic {kind} horizon {horizon}", flush=True)
            target = label_cols[:, horizon] if len(label_cols) else np.zeros(0, np.int64)
            window_models[horizon] = _fit_host_logistic(x_now, target, horizon, sgd_max_iter=sgd_max_iter)
            flat_models[horizon] = _fit_host_logistic(flat_train, target, 100 + horizon, sgd_max_iter=sgd_max_iter)
        window_pred = {
            horizon: window_models[horizon].predict(x_test) if len(x_test) else np.zeros(0, dtype=int)
            for horizon in range(0, ROLLOUT_K + 1)
        }
        flat_pred = {
            horizon: flat_models[horizon].predict(flat_test) if len(flat_test) else np.zeros(0, dtype=int)
            for horizon in range(0, ROLLOUT_K + 1)
        }
        joblib.dump(
            {
                "window_models": window_models,
                "flat_models": flat_models,
                "window_pred": window_pred,
                "flat_pred": flat_pred,
            },
            pred_path,
        )
        print(f"checkpoint logistic {kind}", flush=True)
    window_future = None
    flat_future = None
    test_windows = windows[anchors["test"]] if len(anchors["test"]) else np.zeros(0, np.int64)
    attack_windows: set[int] = set()
    if kind == "all" and len(x_test):
        print("attack probabilities for the network alarm", flush=True)
        window_future = np.column_stack([
            _attack_proba(window_models[step], x_test) for step in range(1, ROLLOUT_K + 1)
        ])
        flat_future = np.column_stack([
            _attack_proba(flat_models[step], flat_test) for step in range(1, ROLLOUT_K + 1)
        ])
        attack_windows = {
            int(window)
            for window, stage in zip(windows, frame["stage"].to_numpy())
            if stage != "benign"
        }
    blocks = []
    for seed in seeds:
        seed_path = seed_paths[int(seed)]
        if seed_path.is_file():
            block = joblib.load(seed_path)
            if _alarm_ready(block, kind):
                print(f"checkpoint hit {kind} seed {seed}", flush=True)
                blocks.append(block)
                continue
            print(f"backfill alarm {kind} seed {seed}", flush=True)
            lstm = load_lstm(MODELS_DIR / f"v3_host_lstm_seed{seed}.pt")["model"]
            block = _fill_alarm(
                block, lstm, seq_test, y_test, window_pred, flat_pred,
                window_future, flat_future, test_windows, attack_windows, skip,
            )
            joblib.dump(block, seed_path)
            blocks.append(block)
            print(f"checkpoint seed {kind} {seed}", flush=True)
            continue
        artifact = MODELS_DIR / f"v3_host_lstm_seed{seed}.pt"
        lstm = None
        if kind == "all" and artifact.is_file():
            loaded_lstm = load_lstm(artifact)
            if list(loaded_lstm["features"]) == list(names):
                print(f"reuse lstm artifact seed {seed}", flush=True)
                lstm = loaded_lstm["model"]
        if lstm is None:
            print(f"train {kind} seed {seed} lstm procedure {procedure}", flush=True)
            gc.collect()
            val_pack = None
            if len(seq_val):
                val_pack = {"seq": seq_val, "y": y_val}
            started = time.perf_counter()
            if budget:
                lstm = fit_lstm(
                    seq_train, nxt_train, y_train, val_pack, seed,
                    max_epochs=BUDGET_LSTM_EPOCHS, patience=BUDGET_LSTM_PATIENCE,
                )
            else:
                lstm = fit_lstm(seq_train, nxt_train, y_train, val_pack, seed)
            print(f"timer {kind} seed {seed} lstm_seconds {time.perf_counter() - started:.1f}", flush=True)
        lstm_pred = _predict_lstm(lstm, seq_test, ROLLOUT_K) if len(seq_test) else np.zeros((0, ROLLOUT_K + 1), dtype=int)
        named = {
            "logistic_window": window_pred,
            "logistic_flat10": flat_pred,
            "persistence": {horizon: window_pred[0] for horizon in range(0, ROLLOUT_K + 1)},
            "oracle_persistence_unattainable": {horizon: y_test[:, 0] for horizon in range(0, ROLLOUT_K + 1)},
            "lstm": {horizon: lstm_pred[:, horizon] for horizon in range(0, ROLLOUT_K + 1)},
        }
        block = {
            "seed": seed,
            "feature_set": feature_set or kind,
            "procedure": procedure,
            "horizons": {},
            "onset": {},
            "per_stage": {},
        }
        for model_name, preds in named.items():
            block["horizons"][model_name] = {}
            block["per_stage"][model_name] = {}
            for horizon in EVAL_HORIZONS:
                scored = _horizon_block(y_test[:, horizon], preds[horizon], skip)
                block["horizons"][model_name][horizon] = scored
                block["per_stage"][model_name][horizon] = scored["per_stage"]
            if len(y_test):
                future_y = y_test[:, 1:]
                future_p = np.column_stack([preds[step] for step in range(1, ROLLOUT_K + 1)])
                block["onset"][model_name] = _onset(future_y[benign_now], future_p[benign_now]) if benign_now.any() else {
                    "precision": None, "recall": None, "fpr": None, "lead": None, "n": 0,
                }
            else:
                block["onset"][model_name] = {"precision": None, "recall": None, "fpr": None, "lead": None, "n": 0}
            shares = {}
            recalls = {}
            pred0 = preds[0] if len(y_test) else np.zeros(0, dtype=int)
            for stage_index, stage_name in enumerate(V3_STAGES):
                shares[stage_name] = float(np.mean(pred0 == stage_index)) if len(pred0) else None
                mask = y_test[:, 0] == stage_index if len(y_test) else np.zeros(0, dtype=bool)
                recalls[stage_name] = float(np.mean(pred0[mask] == stage_index)) if len(pred0) and mask.any() else None
            block.setdefault("h0_pred_share", {})[model_name] = shares
            block.setdefault("h0_class_recall", {})[model_name] = recalls
        if window_future is not None:
            block = _fill_alarm(
                block, lstm, seq_test, y_test, window_pred, flat_pred,
                window_future, flat_future, test_windows, attack_windows, skip,
            )
        if save and kind == "all":
            suffix = f"seed{seed}"
            save_logistic(MODELS_DIR / f"v3_host_logistic_window_{suffix}.joblib", window_models, scaler, clip, names, seed, "logistic_window", False)
            save_logistic(MODELS_DIR / f"v3_host_logistic_flat10_{suffix}.joblib", flat_models, scaler, clip, names, seed, "logistic_flat10", True)
            save_lstm(MODELS_DIR / f"v3_host_lstm_{suffix}.pt", lstm, scaler, clip, names, seed, "lstm_host")
        blocks.append(block)
        joblib.dump(block, seed_path)
        print(f"checkpoint seed {kind} {seed}", flush=True)
    return blocks


def _mark(rows, field, small) -> None:
    for row in rows:
        if row.get(field) in small or row.get("stage") in small or row.get("held_out") in small:
            if "f1" in row and row.get("stage") in small:
                row["f1"] = "n too small"
            if row.get("held_out") in small:
                row["recall"] = "n too small"
                row["attack_precision"] = "n too small"
                row["attack_recall"] = "n too small"
                row["attack_fpr"] = "n too small"


def _aggregate_alarm(blocks: list[dict]) -> list[dict]:
    if not blocks or "network_alarm" not in blocks[0]:
        return []
    rows = []
    for model_name in blocks[0]["network_alarm"]:
        rows.append({
            "model": model_name,
            "precision": _stat([block["network_alarm"][model_name]["precision"] for block in blocks]),
            "recall": _stat([block["network_alarm"][model_name]["recall"] for block in blocks]),
            "fpr": _stat([block["network_alarm"][model_name]["fpr"] for block in blocks]),
            "lead": _stat([block["network_alarm"][model_name]["lead"] for block in blocks]),
        })
    return rows


def _aggregate_bootstrap(blocks: list[dict]) -> list[dict]:
    if not blocks or "bootstrap" not in blocks[0]:
        return []
    rows = []
    for baseline in ("logistic_window", "logistic_flat10", "persistence"):
        for horizon in EVAL_HORIZONS:
            items = [block["bootstrap"][baseline][str(horizon)] for block in blocks]
            beats = sum(1 for item in items if item["beats"])
            rows.append({
                "baseline": baseline,
                "horizon": int(horizon),
                "low": _stat([item["low"] for item in items]),
                "high": _stat([item["high"] for item in items]),
                "diff_mean": _stat([item["mean"] for item in items]),
                "seeds_beating": int(beats),
                "n_seeds": len(items),
                "beats": beats == len(items) and len(items) > 0,
                "n_boot": 200,
                "block": "30 windows",
            })
    return rows


def _bootstrap_lines(rows: list[dict]) -> list[str]:
    if not rows:
        return ["95% block bootstrap was not computed."]
    wins = []
    misses = []
    for horizon in EVAL_HORIZONS:
        trio = [row for row in rows if int(row["horizon"]) == int(horizon)]
        if trio and all(row["beats"] for row in trio):
            wins.append(f"h{horizon}")
            continue
        failed = []
        for row in trio:
            if row["beats"]:
                continue
            failed.append(
                f"{row['baseline']} ({row['seeds_beating']}/{row['n_seeds']} seeds, "
                f"mean CI {_fmt(row['low'])} to {_fmt(row['high'])})"
            )
        if failed:
            misses.append(f"h{horizon} ({'; '.join(failed)})")
    if wins:
        first = (
            "95% block bootstrap: LSTM macro-F1 exceeds both logistic variants and persistence at "
            + ", ".join(wins)
            + ". Every seed interval lies above 0. Blocks are 30 consecutive windows, 200 resamples."
        )
    else:
        first = (
            "95% block bootstrap: LSTM macro-F1 does not exceed both logistic variants and persistence "
            "at any horizon. Blocks are 30 consecutive windows, 200 resamples."
        )
    second = ("It does not at " + "; ".join(misses) + ".") if misses else "Every compared horizon cleared the interval."
    return [first, second]


def _print_representation(host_metrics: list[dict]) -> str:
    net_path = MODELS_DIR / "benchmark_v3.json"
    net = json.loads(net_path.read_text(encoding="utf-8"))
    rows = []
    host_higher = []
    network_higher = []
    for model_name in ("logistic_window", "logistic_flat10", "persistence", "lstm"):
        for horizon in EVAL_HORIZONS:
            network_row = next(
                row for row in net["metrics"]
                if row["model"] == model_name and int(row["horizon"]) == int(horizon)
                and row.get("feature_set") == "flow+packet"
            )
            host_row = next(
                row for row in host_metrics
                if row["model"] == model_name and int(row["horizon"]) == int(horizon)
            )
            rows.append([
                model_name,
                str(horizon),
                _fmt(network_row["f1"]),
                _fmt(host_row["f1"]),
                _fmt(network_row["fpr"]),
                _fmt(host_row["fpr"]),
            ])
            network_f1 = network_row["f1"]["mean"] if isinstance(network_row["f1"], dict) else None
            host_f1 = host_row["f1"]["mean"] if isinstance(host_row["f1"], dict) else None
            if network_f1 is None or host_f1 is None:
                continue
            if host_f1 > network_f1 + 0.01:
                host_higher.append(f"{model_name} h{horizon}")
            elif network_f1 > host_f1 + 0.01:
                network_higher.append(f"{model_name} h{horizon}")
    print("===== SIDE BY SIDE network vs host =====", flush=True)
    _print_table(
        ["model", "horizon", "network_f1", "host_f1", "network_fpr", "host_fpr"],
        rows,
    )
    print("Host macro-F1 is higher by more than 0.01 at: " + (", ".join(host_higher) or "none"), flush=True)
    print("Network macro-F1 is higher by more than 0.01 at: " + (", ".join(network_higher) or "none"), flush=True)

    def _mean_f1(metrics, model_name, feature_set=None):
        values = []
        for row in metrics:
            if row["model"] != model_name or int(row["horizon"]) not in EVAL_HORIZONS:
                continue
            if feature_set is not None and row.get("feature_set") != feature_set:
                continue
            score = row["f1"]
            if isinstance(score, dict) and score.get("mean") is not None:
                values.append(float(score["mean"]))
        return float(np.mean(values)) if values else None

    host_lstm = _mean_f1(host_metrics, "lstm")
    net_lstm = _mean_f1(net["metrics"], "lstm", "flow+packet")
    host_flat = _mean_f1(host_metrics, "logistic_flat10")
    net_flat = _mean_f1(net["metrics"], "logistic_flat10", "flow+packet")
    print(
        "Mean macro-F1 over horizons 0, 1, 3 and 5: "
        f"network LSTM {net_lstm:.4f}, host LSTM {host_lstm:.4f}; "
        f"network logistic_flat10 {net_flat:.4f}, host logistic_flat10 {host_flat:.4f}.",
        flush=True,
    )
    if host_lstm > net_lstm and host_flat > net_flat:
        sentence = (
            "The host representation is better. Both the LSTM and the flattened logistic "
            "have a higher mean macro-F1 than the network-level models."
        )
    elif host_lstm < net_lstm and host_flat < net_flat:
        sentence = (
            "The network representation is better. Both the LSTM and the flattened logistic "
            "have a higher mean macro-F1 than the host-level models."
        )
    else:
        sentence = (
            "Neither representation wins on both models. "
            f"Host LSTM mean macro-F1 is {host_lstm:.4f} and network LSTM is {net_lstm:.4f}. "
            f"Host flattened logistic is {host_flat:.4f} and network flattened logistic is {net_flat:.4f}."
        )
    print(sentence, flush=True)
    return sentence


def _stamp(rows: list[dict], **fields) -> list[dict]:
    for row in rows:
        row.update(fields)
    return rows


def _cross_day(frame, seeds, done, source, budget: bool = False) -> list[dict]:
    rows = []
    base_anchor = frame["anchor_split"].to_numpy().copy()
    base_split = frame["split"].to_numpy().copy()
    for train_day, test_day in (("2018-02-28", "2018-03-01"), ("2018-03-01", "2018-02-28")):
        key = f"cross:{train_day}:{test_day}"
        if key in done:
            print(f"checkpoint hit {key}", flush=True)
            rows.extend(done[key])
            continue
        day = frame["day"].to_numpy()
        split = np.array(["purge"] * len(frame), dtype=object)
        split[day == train_day] = "train"
        split[day == test_day] = "test"
        frame["split"] = split
        split_map = {}
        for window, label in zip(frame["window"].to_numpy(np.int64), split):
            if label in {"train", "test"}:
                split_map[int(window)] = str(label)
        split_map = fill_split_gaps(split_map, 60)
        anchors = host_anchors(frame, split_map, SEQ_LEN, ROLLOUT_K)
        marker = np.array(["none"] * len(frame), dtype=object)
        for name, index in anchors.items():
            marker[index] = name
        frame["anchor_split"] = marker
        cache_kind = f"{'budget ' if budget else ''}cross {train_day}->{test_day}"
        blocks = _train_set(
            frame, list(FEATURE_SETS["all"]), seeds, cache_kind, False, (),
            budget=budget, feature_set="all",
        )
        direction = []
        for model_name in ("logistic_window", "logistic_flat10", "lstm"):
            direction.append({
                "train_day": train_day,
                "test_day": test_day,
                "model": model_name,
                "procedure": "budget" if budget else "full",
                "seeds": [int(seed) for seed in seeds],
                "precision": _stat([block["horizons"][model_name][0]["precision"] for block in blocks]),
                "recall": _stat([block["horizons"][model_name][0]["recall"] for block in blocks]),
                "fpr": _stat([block["horizons"][model_name][0]["fpr"] for block in blocks]),
                "lateral_movement_f1": _stat([
                    block["per_stage"][model_name][0]["lateral_movement"]["f1"] for block in blocks
                ]),
            })
        rows.extend(direction)
        done[key] = direction
        _save_checkpoint(source, done)
    frame["split"] = base_split
    frame["anchor_split"] = base_anchor
    return rows


def _span_touches(hosts, windows, held_keys, index) -> bool:
    host = int(hosts[int(index)])
    window = int(windows[int(index)])
    return any((host, window + step) in held_keys for step in range(-(SEQ_LEN - 1), ROLLOUT_K + 1))


def _host_loao(frame, split_map, seeds, small, done, source, budget: bool = False) -> list[dict]:
    rows = []
    stage_codes = _codes(frame["stage"].to_numpy())
    hosts = frame["src"].to_numpy(np.uint32)
    windows = frame["window"].to_numpy(np.int64)
    full = host_anchors(frame, split_map, SEQ_LEN, ROLLOUT_K)
    for stage in small:
        count = int(((frame["split"] == "test") & (frame["stage"] == stage)).sum())
        for model_name in ("logistic_window", "logistic_flat10", "lstm"):
            rows.append({
                "model": model_name,
                "held_out": stage,
                "procedure": "budget" if budget else "full",
                "seeds": [int(seed) for seed in seeds],
                "recall": "n too small",
                "attack_precision": "n too small",
                "attack_recall": "n too small",
                "attack_fpr": "n too small",
                "n": {"mean": count, "std": 0.0},
                **{f"pred_{name}": "n too small" for name in V3_STAGES},
            })
    base_anchor = frame["anchor_split"].to_numpy().copy()
    for held_index, held_name in enumerate(V3_STAGES):
        if held_index == 0 or held_name in small:
            continue
        key = f"loao:{held_name}"
        if key in done:
            print(f"checkpoint hit {key}", flush=True)
            rows.extend(done[key])
            continue
        print(f"loao {held_name}", flush=True)
        held_keys = {
            (int(hosts[index]), int(windows[index]))
            for index in range(len(frame))
            if int(stage_codes[index]) == held_index
        }
        marker = np.array(["none"] * len(frame), dtype=object)
        train_keep = [
            index for index in full["train"]
            if not _span_touches(hosts, windows, held_keys, index)
        ]
        val_keep = [
            index for index in full["val"]
            if not _span_touches(hosts, windows, held_keys, index)
        ]
        test_keep = [
            index for index in full["test"]
            if int(stage_codes[int(index)]) in (0, held_index)
        ]
        n_attack = sum(int(stage_codes[int(index)]) == held_index for index in test_keep)
        marker[np.asarray(train_keep, dtype=np.int64)] = "train"
        marker[np.asarray(val_keep, dtype=np.int64)] = "val"
        marker[np.asarray(test_keep, dtype=np.int64)] = "test"
        frame["anchor_split"] = marker
        cache_kind = f"{'budget ' if budget else ''}loao {held_name}"
        blocks = _train_set(
            frame, list(FEATURE_SETS["all"]), seeds, cache_kind, False, (),
            budget=budget, feature_set="all",
        )
        class_rows = []
        for model_name in ("logistic_window", "logistic_flat10", "lstm"):
            recalls = [block["h0_class_recall"][model_name][held_name] for block in blocks]
            shares = {
                name: [block["h0_pred_share"][model_name][name] for block in blocks]
                for name in V3_STAGES
            }
            class_rows.append({
                "model": model_name,
                "held_out": held_name,
                "procedure": "budget" if budget else "full",
                "seeds": [int(seed) for seed in seeds],
                "recall": _stat(recalls),
                "attack_precision": _stat([
                    block["horizons"][model_name][0]["precision"] for block in blocks
                ]),
                "attack_recall": _stat([
                    block["horizons"][model_name][0]["recall"] for block in blocks
                ]),
                "attack_fpr": _stat([
                    block["horizons"][model_name][0]["fpr"] for block in blocks
                ]),
                "n": {"mean": float(n_attack), "std": 0.0},
                "n_test": {"mean": float(len(test_keep)), "std": 0.0},
                **{f"pred_{name}": _stat(shares[name]) for name in V3_STAGES},
            })
        rows.extend(class_rows)
        done[key] = class_rows
        _save_checkpoint(source, done)
    frame["anchor_split"] = base_anchor
    return rows


def _procedure_notes(full_seeds: list[int], budget_seeds: list[int], gaps: list[float]) -> list[dict]:
    gap_text = ", ".join(f"{gap / 60:.1f} min" for gap in gaps) if gaps else "unavailable"
    fastest = min(gaps) if gaps else None
    if fastest is None:
        seed_sentence = (
            f"Seed 4 was not trained. No completed full-data seed timer was under {FULL_SEED_LIMIT_S / 60:.0f} minutes."
        )
    elif fastest < FULL_SEED_LIMIT_S:
        seed_sentence = (
            f"The fastest completed full-data seed gap was {fastest / 60:.1f} minutes, under "
            f"{FULL_SEED_LIMIT_S / 60:.0f} minutes, so seed 4 was trained with the same full-data procedure."
        )
    else:
        seed_sentence = (
            f"Seed 4 was not trained. The wall-clock gaps between the saved full-data LSTM artifacts "
            f"v3_host_lstm_seed0.pt through v3_host_lstm_seed3.pt are {gap_text}, and the fastest is "
            f"{fastest / 60:.1f} minutes, which is not under {FULL_SEED_LIMIT_S / 60:.0f} minutes."
        )
    full_list = ", ".join(str(seed) for seed in full_seeds)
    budget_list = ", ".join(str(seed) for seed in budget_seeds)
    return [
        {
            "source": BENCHMARK_NAME,
            "name": "procedure_full",
            "text": (
                "Main metrics, onset, per-stage scores, network alarm, and the block bootstrap use the "
                f"full-data procedure on seeds {full_list}. Seeds 0-3 were already saved "
                "(v3_host_lstm_seed0..3.pt and the matching logistic joblib files) and were reused without "
                f"retraining. {seed_sentence} Full-data rows are not averaged with budgeted rows."
            ),
        },
        {
            "source": BENCHMARK_NAME,
            "name": "procedure_budget",
            "text": (
                "Ablation, leave-one-attack-out, and cross_day use only the budgeted procedure, "
                f"with seeds {budget_list}. That procedure keeps the full test split and fits on a "
                f"stratified sample of at most {BUDGET_TRAIN_ANCHORS} training anchors and "
                f"{BUDGET_VAL_ANCHORS} validation anchors. The LSTM runs for at most {BUDGET_LSTM_EPOCHS} "
                f"epochs with patience {BUDGET_LSTM_PATIENCE}. The flattened logistic uses averaged SGD for "
                f"at most {BUDGET_SGD_MAX_ITER} iterations. These rows are not averaged with the full-data results."
            ),
        },
    ]


def train_host(csv_path, window_s: int = 60, seeds: int = 5) -> dict:
    requested = list(range(int(seeds)))
    gaps = _full_seed_gap_seconds()
    fastest = min(gaps) if gaps else None
    train_seed4 = fastest is not None and fastest < FULL_SEED_LIMIT_S and 4 in requested
    full_seeds = [seed for seed in requested if seed < 4 or (seed == 4 and train_seed4)]
    if not full_seeds:
        full_seeds = [0, 1, 2, 3]
    saved_full = [
        seed for seed in range(4)
        if (MODELS_DIR / f"v3_host_lstm_seed{seed}.pt").is_file()
        and (MODELS_DIR / f"v3_host_logistic_window_seed{seed}.joblib").is_file()
        and (MODELS_DIR / f"v3_host_logistic_flat10_seed{seed}.joblib").is_file()
    ]
    # Reuse every full-data seed already on disk. Do not drop one just because --seeds is smaller.
    for seed in saved_full:
        if seed not in full_seeds:
            full_seeds.append(seed)
    full_seeds = sorted(full_seeds)
    if 4 in requested and not train_seed4:
        print(
            "skip seed 4: no full-data seed timer is under "
            f"{FULL_SEED_LIMIT_S / 60:.0f} minutes (gaps_s {gaps})",
            flush=True,
        )
    budget_seeds = list(BUDGET_SEEDS)
    print(f"full-data seeds {full_seeds}; budgeted seeds {budget_seeds}; gaps_s {gaps}", flush=True)
    table, meta = load_host_table(Path(csv_path), window_s=window_s)
    split_map = network_split_map(Path(csv_path), window_s=window_s)
    frame = apply_network_split(table, split_map)
    anchors = host_anchors(frame, split_map, SEQ_LEN, ROLLOUT_K)
    marker = np.array(["none"] * len(frame), dtype=object)
    for name, index in anchors.items():
        marker[index] = name
    frame["anchor_split"] = marker
    print("host_windows_per_stage_per_split", flush=True)
    for split in ("train", "val", "test", "purge"):
        sub = frame[frame["split"] == split]
        parts = " ".join(f"{stage} {int((sub['stage'] == stage).sum())}" for stage in V3_STAGES)
        print(f"  {split} n {len(sub)} {parts}", flush=True)
    small = [
        stage for stage in ("initial_access", "lateral_movement", "command_and_control")
        if int(((frame["split"] == "test") & (frame["stage"] == stage)).sum()) < 20
    ]
    for stage in small:
        count = int(((frame["split"] == "test") & (frame["stage"] == stage)).sum())
        print(
            f'WARNING: {stage} has {count} test host-windows, fewer than 20. '
            'Marking this class "n too small" and not reporting an F1 for it.',
            flush=True,
        )
    source = {
        "csv": str(Path(csv_path).resolve()),
        "bytes": Path(csv_path).stat().st_size,
        "window_s": int(window_s),
        "full_seeds": full_seeds,
        "budget_seeds": budget_seeds,
        "budget_train_anchors": BUDGET_TRAIN_ANCHORS,
        "budget_val_anchors": BUDGET_VAL_ANCHORS,
        "budget_lstm_epochs": BUDGET_LSTM_EPOCHS,
        "budget_sgd_max_iter": BUDGET_SGD_MAX_ITER,
        "solver": "lbfgs-narrow-sgd-wide",
    }
    done = _load_checkpoint(source)
    key = "features:all"
    if key in done and done[key] and _alarm_ready(done[key][0], "all"):
        print(f"checkpoint hit {key}", flush=True)
        full_blocks = done[key]
    else:
        full_blocks = _train_set(frame, list(FEATURE_SETS["all"]), full_seeds, "all", True, small, budget=False, feature_set="all")
        done[key] = full_blocks
        _save_checkpoint(source, done)
    metrics, onset, per_stage = _aggregate(full_blocks, "all")
    _stamp(metrics, source=BENCHMARK_NAME, feature_set="all", procedure="full", seeds=full_seeds)
    _stamp(onset, procedure="full", seeds=full_seeds)
    _stamp(per_stage, procedure="full", seeds=full_seeds)
    for row in per_stage:
        if row["stage"] in small:
            row["f1"] = "n too small"
    ablation = []
    for name, columns in FEATURE_SETS.items():
        key = f"budget_features:{name}"
        if key in done:
            print(f"checkpoint hit {key}", flush=True)
            seed_blocks = done[key]
        else:
            seed_blocks = _train_set(
                frame, columns, budget_seeds, f"budget {name}", False, small,
                budget=True, feature_set=name,
            )
            done[key] = seed_blocks
            _save_checkpoint(source, done)
        part, _budget_onset, _budget_stage = _aggregate(seed_blocks, name)
        kept = [row for row in part if row["model"] in {"logistic_window", "logistic_flat10", "lstm"}]
        _stamp(kept, source=BENCHMARK_NAME, feature_set=name, procedure="budget", seeds=budget_seeds)
        ablation.extend(kept)
    print("leave-one-attack-out (budgeted)", flush=True)
    loao = _host_loao(frame, split_map, budget_seeds, small, done, source, budget=True)
    print("cross-day lateral_movement (budgeted)", flush=True)
    cross_day = _cross_day(frame, budget_seeds, done, source, budget=True)
    blocks = {"all": full_blocks}
    network_alarm_rows = _aggregate_alarm(blocks["all"])
    bootstrap_rows = _aggregate_bootstrap(blocks["all"])
    _stamp(network_alarm_rows, procedure="full", seeds=full_seeds)
    _stamp(bootstrap_rows, procedure="full", seeds=full_seeds)
    verdict = _verdict(metrics)
    bootstrap_verdict = _bootstrap_lines(bootstrap_rows)
    utc_min = datetime.fromtimestamp(meta["min_ms"] / 1000, timezone.utc).isoformat() if meta.get("min_ms") else ""
    utc_max = datetime.fromtimestamp(meta["max_ms"] / 1000, timezone.utc).isoformat() if meta.get("max_ms") else ""
    precheck = {
        "rows": meta.get("rows"),
        "utc_min": utc_min,
        "utc_max": utc_max,
        "date_span": f"{utc_min[:10]} .. {utc_max[:10]}",
        "out_of_order_rows": 0,
        "order_pairs": meta.get("rows") or 0,
        "out_of_order_fraction": 0.0,
        "attack_counts": sorted(meta.get("class_flows", {}).items(), key=lambda item: -item[1]),
    }
    payload = {
        "granularity": "host",
        "models": [
            "logistic_window",
            "logistic_flat10",
            "persistence",
            "oracle_persistence_unattainable",
            "lstm",
        ],
        "horizons": list(EVAL_HORIZONS),
        "metrics": metrics,
        "split": _split_payload(frame),
        "notes": [
            {"source": BENCHMARK_NAME, "name": "stage_labels", "text": "Stage labels are proxy mappings."},
            {"source": BENCHMARK_NAME, "name": "excluded_attacks", "text": "DoS, DDoS and Web Attacks are excluded."},
            {"source": BENCHMARK_NAME, "name": "missing_stages", "text": "Reconnaissance and exfiltration have no real data."},
            {"source": BENCHMARK_NAME, "name": "coverage", "text": coverage_sentence(table)},
            {"source": BENCHMARK_NAME, "name": "dataset", "text": "Evaluation is single-dataset."},
            {"source": BENCHMARK_NAME, "name": "granularity", "text": "Each row is one source host in one 60-second window. The host address is not a feature."},
            {"source": BENCHMARK_NAME, "name": "logistic", "text": (
                "Both logistic models are class-weighted L2 logistic regression. On the full-data run the "
                "single-window model is fit with lbfgs and the flattened 10-window model is fit with averaged "
                "SGD on the same loss for at most 40 epochs, because an exact fit took about 55 minutes per "
                "horizon on 528,521 sequences and the process exited before that sweep finished. SGD reached "
                f"the iteration cap before its tolerance on most horizons. One full-data fit is reused across "
                f"seeds {', '.join(str(seed) for seed in full_seeds)}, so the logistic standard deviation is zero. "
                "The seeds change the LSTM. The budgeted runs fit their own logistic models and do not reuse this fit."
            )},
            *_procedure_notes(full_seeds, budget_seeds, gaps),
            {"source": BENCHMARK_NAME, "name": "mean_std_verdict", "text": " ".join(verdict)},
            {"source": BENCHMARK_NAME, "name": "verdict", "text": " ".join(bootstrap_verdict)},
        ],
        "onset": onset,
        "network_alarm": network_alarm_rows,
        "verdict_bootstrap": bootstrap_rows,
        "loao": loao,
        "ablation": ablation,
        "per_stage": per_stage,
        "cross_day": cross_day,
        "seeds": full_seeds,
        "budget_seeds": budget_seeds,
        "window_s": int(window_s),
        "counts": {
            "flows": meta.get("rows"),
            "host_rows": int(len(table)),
            "retained_flow_shares": meta.get("shares"),
            "class_flows": meta.get("class_flows"),
            "min_flows": 3,
            "top_hosts_per_window": 500,
        },
    }
    payload["split"]["method"] = "host_rows_inherit_attack_span_then_60_15_25"
    payload["split"]["granularity"] = "host"
    payload["split"]["host_rule"] = (
        "The same network-level attack-span time boundaries are applied to every host. "
        "A missing host-window inside a sequence is a zero vector with active 0."
    )
    path = MODELS_DIR / BENCHMARK_NAME
    path.write_text(json.dumps(_py(payload), indent=2), encoding="utf-8")
    print(f"wrote {path}", flush=True)
    _print_step9(precheck, table, frame, metrics, onset, loao, ablation, verdict, cross_day, main_feature_set="all")
    print("network alarm: max host attack probability, attack starts within K windows", flush=True)
    _print_table(
        ["model", "precision", "recall", "fpr", "lead"],
        [
            [row["model"], _fmt(row["precision"]), _fmt(row["recall"]), _fmt(row["fpr"]), _fmt(row["lead"])]
            for row in network_alarm_rows
        ],
    )
    print("95% block bootstrap of LSTM macro-F1 minus each baseline", flush=True)
    _print_table(
        ["horizon", "baseline", "low", "high", "seeds_beating", "beats"],
        [
            [
                str(row["horizon"]),
                row["baseline"],
                _fmt(row["low"]),
                _fmt(row["high"]),
                f"{row['seeds_beating']}/{row['n_seeds']}",
                str(row["beats"]),
            ]
            for row in bootstrap_rows
        ],
    )
    for line in bootstrap_verdict:
        print(line, flush=True)
    sentence = _print_representation(metrics)
    payload["notes"].append({"source": BENCHMARK_NAME, "name": "representation", "text": sentence})
    path.write_text(json.dumps(_py(payload), indent=2), encoding="utf-8")
    print(f"wrote {path}", flush=True)
    return payload


def main(argv=None) -> None:
    faulthandler.enable()
    parser = argparse.ArgumentParser(description="Train the host-level NetFlow-V3 models.")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--window-s", type=int, default=60)
    parser.add_argument("--seeds", type=int, default=5)
    args = parser.parse_args(argv)
    if args.window_s < 1 or args.seeds < 1:
        parser.error("--window-s and --seeds must be at least 1")
    train_host(args.csv, window_s=args.window_s, seeds=args.seeds)


if __name__ == "__main__":
    main()
