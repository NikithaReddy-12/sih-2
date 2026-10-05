"""NetFlow-V3 models: two logistic baselines, persistence, and an LSTM world model.

Feature names, the scaler, and the clip thresholds are stored inside each artifact.
Loading reads that feature list from the artifact.
"""
from __future__ import annotations

import io
import json
import random
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_recall_fscore_support
from sklearn.preprocessing import StandardScaler
from torch import nn

from .baseline import MODELS_DIR
from .config import (
    AUX_WEIGHT,
    EVAL_HORIZONS,
    FEATURES,
    FLOW_FEATURES,
    HEAVY_FEATURES,
    ROLLOUT_K,
    SEQ_LEN,
    V3_STAGES,
)
from .netflow_v3 import (
    build_feature_frame,
    coverage_sentence,
    load_windows,
    modeling_frame,
    sequence_anchors,
)

HIDDEN = 64
EMBEDDING = 16
MAX_EPOCHS = 25
PATIENCE = 5
BATCH = 256
LR = 1e-3
WEIGHT_DECAY = 1e-4
BENCHMARK_NAME = "benchmark_v3.json"


class WorldV3(nn.Module):
    """Encode seq_len windows, classify the current stage, roll K steps, predict the next feature vector."""

    def __init__(self, n_features: int, n_stages: int, hidden: int = HIDDEN, embedding: int = EMBEDDING):
        super().__init__()
        self.encoder = nn.LSTM(n_features, hidden, num_layers=1, batch_first=True)
        self.now = nn.Linear(hidden, n_stages)
        self.stage_emb = nn.Embedding(n_stages, embedding)
        self.dec_in = nn.Linear(embedding, hidden)
        self.decoder = nn.LSTMCell(hidden, hidden)
        self.future = nn.Linear(hidden, n_stages)
        self.next_feat = nn.Linear(hidden, n_features)

    def forward(self, x: torch.Tensor, steps: int):
        _, (h, c) = self.encoder(x)
        h, c = h[-1], c[-1]
        now_logits = self.now(h)
        nxt = self.next_feat(h)
        prev = torch.softmax(now_logits, dim=-1)
        futures = []
        for _ in range(int(steps)):
            embedded = prev @ self.stage_emb.weight
            h, c = self.decoder(self.dec_in(embedded), (h, c))
            step = self.future(h)
            futures.append(step)
            prev = torch.softmax(step, dim=-1)
        future_logits = torch.stack(futures, dim=1) if futures else now_logits[:, None, :][:, :0, :]
        return now_logits, future_logits, nxt


class ConstantStageModel:
    """Used when a training fold contains a single stage."""

    def __init__(self, label: int, classes: list[int]):
        self.classes_ = np.asarray(classes, dtype=int)
        self.label = int(label)

    def predict(self, values) -> np.ndarray:
        return np.full(len(values), self.label, dtype=int)


def set_seed(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def fit_clip_scaler(train: np.ndarray, names: list[str], heavy: list[str]) -> tuple[dict, StandardScaler, np.ndarray]:
    clipped = np.array(train, dtype=np.float64, copy=True)
    clip = {}
    for name in heavy:
        if name not in names:
            continue
        column = names.index(name)
        limit = float(np.quantile(clipped[:, column], 0.995))
        clip[name] = limit
        clipped[:, column] = np.minimum(clipped[:, column], limit)
    scaler = StandardScaler().fit(clipped)
    return clip, scaler, clipped


def transform_matrix(values: np.ndarray, names: list[str], clip: dict, scaler: StandardScaler) -> np.ndarray:
    clipped = np.array(values, dtype=np.float64, copy=True)
    for name, limit in clip.items():
        column = names.index(name)
        clipped[:, column] = np.minimum(clipped[:, column], float(limit))
    return scaler.transform(clipped).astype(np.float32)


def _prep_blob(scaler: StandardScaler, clip: dict, features: list[str]) -> bytes:
    buffer = io.BytesIO()
    joblib.dump({"scaler": scaler, "clip_high": clip, "features": list(features)}, buffer)
    return buffer.getvalue()


def _read_prep(blob: dict) -> tuple[StandardScaler, dict, list[str]]:
    features = [str(name) for name in blob["features"]]
    prep = joblib.load(io.BytesIO(blob["prep"]))
    saved = [str(name) for name in prep["features"]]
    if saved != features:
        raise RuntimeError("Artifact feature list does not match the stored scaler features.")
    return prep["scaler"], dict(prep["clip_high"]), features


def save_lstm(path: Path, model: WorldV3, scaler, clip, features, seed: int, kind: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "features": list(features),
            "stages": list(V3_STAGES),
            "prep": _prep_blob(scaler, clip, features),
            "config": {
                "seq_len": SEQ_LEN,
                "k": ROLLOUT_K,
                "hidden": int(model.encoder.hidden_size),
                "embedding": int(model.stage_emb.embedding_dim),
                "aux_weight": AUX_WEIGHT,
                "seed": int(seed),
                "kind": kind,
                "n_features": len(features),
                "n_stages": len(V3_STAGES),
            },
        },
        path,
    )


def load_lstm(path: Path) -> dict:
    try:
        blob = torch.load(path, map_location="cpu", weights_only=False)
    except TypeError:
        blob = torch.load(path, map_location="cpu")
    scaler, clip, features = _read_prep(blob)
    stages = [str(name) for name in blob["stages"]]
    config = dict(blob["config"])
    model = WorldV3(len(features), len(stages), hidden=int(config["hidden"]), embedding=int(config["embedding"]))
    model.load_state_dict(blob["state_dict"])
    model.eval()
    return {"model": model, "scaler": scaler, "clip_high": clip, "features": features, "stages": stages, "config": config}


def save_logistic(path: Path, models: dict, scaler, clip, features, seed: int, kind: str, flat: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "models": models,
            "prep": _prep_blob(scaler, clip, features),
            "features": list(features),
            "stages": list(V3_STAGES),
            "seed": int(seed),
            "kind": kind,
            "flat_seq_len": SEQ_LEN if flat else 1,
        },
        path,
    )


def load_logistic(path: Path) -> dict:
    blob = joblib.load(path)
    scaler, clip, features = _read_prep(blob)
    return {
        "models": blob["models"],
        "scaler": scaler,
        "clip_high": clip,
        "features": features,
        "stages": [str(name) for name in blob["stages"]],
        "seed": int(blob["seed"]),
        "kind": blob["kind"],
        "flat_seq_len": int(blob["flat_seq_len"]),
    }


def _fit_logistic(x_train: np.ndarray, y_train: np.ndarray, seed: int):
    classes = sorted(int(value) for value in np.unique(y_train))
    if len(classes) < 2:
        label = classes[0] if classes else 0
        return ConstantStageModel(label, list(range(len(V3_STAGES))))
    model = LogisticRegression(
        class_weight="balanced",
        max_iter=500,
        solver="lbfgs",
        random_state=int(seed),
    )
    model.fit(x_train, y_train)
    return model


def _class_weights(y_current: np.ndarray) -> np.ndarray:
    counts = np.bincount(y_current.astype(int), minlength=len(V3_STAGES)).astype(np.float64)
    weights = np.zeros(len(V3_STAGES), dtype=np.float64)
    present = counts > 0
    if present.any():
        weights[present] = counts[present].sum() / (present.sum() * counts[present])
    return weights


def _macro_f1(y_true: np.ndarray, y_pred: np.ndarray, skip_labels=()) -> float:
    labels = [
        index for index in range(len(V3_STAGES))
        if np.any(y_true == index) and index not in skip_labels
    ]
    if not labels:
        return 0.0
    return float(f1_score(y_true, y_pred, average="macro", labels=labels, zero_division=0))


def _attack_rates(y_true: np.ndarray, y_pred: np.ndarray) -> tuple[float, float, float]:
    truth = y_true != 0
    pred = y_pred != 0
    tp = int(np.sum(truth & pred))
    fp = int(np.sum(~truth & pred))
    tn = int(np.sum(~truth & ~pred))
    fn = int(np.sum(truth & ~pred))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return precision, recall, fpr


def _per_stage(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    _, _, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(range(len(V3_STAGES))), zero_division=0
    )
    out = {}
    for index, name in enumerate(V3_STAGES):
        count = int(support[index])
        out[name] = {"f1": None if count == 0 else float(f1[index]), "support": count}
    return out


def stack_sequences(matrix: np.ndarray, stages: np.ndarray, anchors: np.ndarray, seq_len: int, k: int):
    count = len(anchors)
    features = matrix.shape[1]
    seqs = np.empty((count, seq_len, features), np.float32)
    nxt = np.empty((count, features), np.float32)
    ys = np.empty((count, k + 1), np.int64)
    for row, position in enumerate(anchors):
        position = int(position)
        seqs[row] = matrix[position - seq_len + 1:position + 1]
        nxt[row] = matrix[position + 1]
        ys[row] = stages[position:position + k + 1]
    return seqs, nxt, ys


def _predict_lstm(model: WorldV3, seqs: np.ndarray, k: int) -> np.ndarray:
    model.eval()
    preds = np.empty((len(seqs), k + 1), dtype=int)
    with torch.no_grad():
        for start in range(0, len(seqs), BATCH):
            batch = torch.tensor(seqs[start:start + BATCH], dtype=torch.float32)
            now, future, _ = model(batch, k)
            preds[start:start + BATCH, 0] = torch.argmax(now, dim=-1).cpu().numpy()
            if k:
                preds[start:start + BATCH, 1:] = torch.argmax(future, dim=-1).cpu().numpy()
    return preds


def fit_lstm(seqs, nxt, ys, val, seed: int, max_epochs: int | None = None, patience: int | None = None) -> WorldV3:
    set_seed(seed)
    model = WorldV3(seqs.shape[2], len(V3_STAGES))
    if len(seqs) == 0:
        return model
    weight = torch.tensor(_class_weights(ys.reshape(-1)), dtype=torch.float32)
    opt = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    rng = np.random.default_rng(seed)
    best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
    best_score = -1.0
    wait = 0
    epochs = MAX_EPOCHS if val is not None else 8
    if max_epochs is not None:
        epochs = int(max_epochs)
    stop_after = PATIENCE if patience is None else int(patience)
    for epoch in range(epochs):
        model.train()
        order = rng.permutation(len(seqs))
        total = 0.0
        seen = 0
        for start in range(0, len(order), BATCH):
            pick = order[start:start + BATCH]
            xb = torch.tensor(seqs[pick], dtype=torch.float32)
            yb = torch.tensor(ys[pick], dtype=torch.long)
            nb = torch.tensor(nxt[pick], dtype=torch.float32)
            now, future, pred_next = model(xb, ROLLOUT_K)
            loss = F.cross_entropy(now, yb[:, 0], weight=weight)
            for step in range(ROLLOUT_K):
                loss = loss + F.cross_entropy(future[:, step], yb[:, step + 1], weight=weight)
            loss = loss / (1 + ROLLOUT_K) + AUX_WEIGHT * F.mse_loss(pred_next, nb)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += float(loss.item()) * len(pick)
            seen += len(pick)
        if val is None:
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
            print(f"lstm seed {seed} epoch {epoch} loss {total / max(seen, 1):.4f}", flush=True)
            continue
        pred = _predict_lstm(model, val["seq"], ROLLOUT_K)
        score = float(np.mean([_macro_f1(val["y"][:, horizon], pred[:, horizon]) for horizon in EVAL_HORIZONS]))
        print(f"lstm seed {seed} epoch {epoch} val_macro_f1 {score:.4f} loss {total / max(seen, 1):.4f}", flush=True)
        if score > best_score + 1e-4:
            best_score = score
            best_state = {key: value.detach().cpu().clone() for key, value in model.state_dict().items()}
            wait = 0
        else:
            wait += 1
            if wait >= stop_after:
                break
    model.load_state_dict(best_state)
    model.eval()
    return model


def _onset(y_future: np.ndarray, pred_future: np.ndarray) -> dict:
    """y_future and pred_future are [N, K] for steps t+1..t+K. The current window is benign."""
    truth = np.any(y_future != 0, axis=1)
    pred = np.any(pred_future != 0, axis=1)
    tp = int(np.sum(truth & pred))
    fp = int(np.sum(~truth & pred))
    tn = int(np.sum(~truth & ~pred))
    fn = int(np.sum(truth & ~pred))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    leads = []
    hit = np.flatnonzero(truth & pred)
    for row in hit:
        true_h = int(np.flatnonzero(y_future[row] != 0)[0]) + 1
        pred_h = int(np.flatnonzero(pred_future[row] != 0)[0]) + 1
        leads.append(true_h - pred_h)
    lead = float(np.mean(leads)) if leads else None
    return {"precision": precision, "recall": recall, "fpr": fpr, "lead": lead, "n": int(len(y_future))}


def _horizon_block(y_true: np.ndarray, y_pred: np.ndarray, skip_labels=()) -> dict:
    precision, recall, fpr = _attack_rates(y_true, y_pred)
    return {
        "f1": _macro_f1(y_true, y_pred, skip_labels),
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
        "per_stage": _per_stage(y_true, y_pred),
    }


def _stat(values) -> dict:
    clean = []
    for value in values:
        if value is None:
            continue
        number = float(value)
        if np.isnan(number):
            continue
        clean.append(number)
    if not clean:
        return {"mean": None, "std": None}
    arr = np.asarray(clean, dtype=np.float64)
    std = float(arr.std(ddof=1)) if len(arr) > 1 else 0.0
    return {"mean": round(float(arr.mean()), 6), "std": round(std, 6)}


def _py(value):
    if isinstance(value, dict):
        return {str(key): _py(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_py(item) for item in value]
    if isinstance(value, (np.floating, float)):
        number = float(value)
        if np.isnan(number) or np.isinf(number):
            return None
        return number
    if isinstance(value, (np.integer, int)) and not isinstance(value, bool):
        return int(value)
    return value


def _beats(lstm: dict, other: dict) -> bool:
    if lstm["mean"] is None or other["mean"] is None:
        return False
    margin = max(float(lstm["std"] or 0), float(other["std"] or 0))
    return float(lstm["mean"]) > float(other["mean"]) + margin


def _verdict(metrics: list[dict]) -> list[str]:
    by_model = {}
    for row in metrics:
        by_model.setdefault(row["model"], {})[int(row["horizon"])] = row
    horizons = list(EVAL_HORIZONS)
    wins = []
    losses = []
    for horizon in horizons:
        lstm = by_model.get("lstm", {}).get(horizon)
        others = [by_model.get(name, {}).get(horizon) for name in ("logistic_window", "logistic_flat10", "persistence")]
        if lstm is None or any(item is None for item in others):
            losses.append(f"h{horizon} missing")
            continue
        beaten = []
        missed = []
        for name, other in zip(("logistic_window", "logistic_flat10", "persistence"), others):
            if _beats(lstm["f1"], other["f1"]):
                beaten.append(name)
            else:
                missed.append(name)
        if not missed:
            wins.append(f"h{horizon}")
        else:
            detail = ", ".join(
                f"{name} lstm {_fmt(lstm['f1'])} vs {_fmt(other['f1'])}"
                for name, other in zip(("logistic_window", "logistic_flat10", "persistence"), others)
                if name in missed
            )
            losses.append(f"h{horizon} ({detail})")
    line1 = (
        "LSTM beats both logistic variants and persistence by more than one standard deviation on macro-F1 at "
        + (", ".join(wins) if wins else "no horizon")
        + "."
    )
    line2 = "It does not at " + ("; ".join(losses) if losses else "any reported horizon") + "."
    return [line1, line2]


def _fmt(stat) -> str:
    if isinstance(stat, str):
        return stat
    if not isinstance(stat, dict) or stat.get("mean") is None:
        return "n/a"
    return f"{stat['mean']:.4f}±{stat['std']:.4f}"


def _print_table(headers: list[str], rows: list[list[str]]) -> None:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    def format_row(row):
        return "  ".join(cell.ljust(widths[index]) for index, cell in enumerate(row))
    print(format_row(headers), flush=True)
    for row in rows:
        print(format_row(row), flush=True)


def _window_matrix(frame, names: list[str]) -> np.ndarray:
    return build_feature_frame(frame)[names].to_numpy(np.float64)


def _codes(frame) -> np.ndarray:
    mapping = {name: index for index, name in enumerate(V3_STAGES)}
    return frame["stage"].map(mapping).to_numpy(np.int64)


def _train_feature_set(frame, names, seeds, kind_prefix: str, save: bool, skip_stages=()) -> list[dict]:
    heavy = [name for name in HEAVY_FEATURES if name in names]
    raw = _window_matrix(frame, names)
    stages = _codes(frame)
    train_rows = frame.index[frame["split"] == "train"].to_numpy()
    clip, scaler, _ = fit_clip_scaler(raw[train_rows], names, heavy)
    scaled = transform_matrix(raw, names, clip, scaler)
    anchors = {split: sequence_anchors(frame, split, SEQ_LEN, ROLLOUT_K) for split in ("train", "val", "test")}
    print(
        f"anchors {kind_prefix} " + " ".join(f"{split} {len(anchors[split])}" for split in anchors),
        flush=True,
    )
    skip_labels = tuple(V3_STAGES.index(name) for name in skip_stages)
    return [
        _fit_seed_models(
            scaled, stages, anchors, names, clip, scaler, seed, kind_prefix, save, kind_prefix, skip_labels,
        )
        for seed in seeds
    ]


def _fit_seed_models(scaled, stages, anchors, names, clip, scaler, seed, kind_prefix, save, window_prefix, skip_labels=()) -> dict:
    """Train one seed. kind_prefix is 'flow+packet' or 'flow'."""
    x_cur = {split: scaled[idx] for split, idx in anchors.items()}
    flat = {}
    width = SEQ_LEN * len(names)
    for split, idx in anchors.items():
        if len(idx) == 0:
            flat[split] = np.zeros((0, width), np.float32)
        else:
            flat[split] = np.stack(
                [scaled[int(p) - SEQ_LEN + 1:int(p) + 1].reshape(-1) for p in idx],
                axis=0,
            ).astype(np.float32)
    y = {
        (split, horizon): stages[idx + horizon]
        for split, idx in anchors.items()
        for horizon in range(0, ROLLOUT_K + 1)
    }
    print(f"train {kind_prefix} seed {seed} logistic+lstm", flush=True)
    window_models = {}
    flat_models = {}
    for horizon in range(0, ROLLOUT_K + 1):
        window_models[horizon] = _fit_logistic(x_cur["train"], y[("train", horizon)], seed + horizon)
        flat_models[horizon] = _fit_logistic(flat["train"], y[("train", horizon)], seed + 100 + horizon)
    seq_train, nxt_train, y_train = stack_sequences(scaled, stages, anchors["train"], SEQ_LEN, ROLLOUT_K) if len(anchors["train"]) else (
        np.zeros((0, SEQ_LEN, len(names)), np.float32),
        np.zeros((0, len(names)), np.float32),
        np.zeros((0, ROLLOUT_K + 1), np.int64),
    )
    val_pack = None
    if len(anchors["val"]):
        seq_val, _, y_val = stack_sequences(scaled, stages, anchors["val"], SEQ_LEN, ROLLOUT_K)
        val_pack = {"seq": seq_val, "y": y_val}
    lstm = fit_lstm(seq_train, nxt_train, y_train, val_pack, seed)
    seq_test, _, y_test = stack_sequences(scaled, stages, anchors["test"], SEQ_LEN, ROLLOUT_K) if len(anchors["test"]) else (
        np.zeros((0, SEQ_LEN, len(names)), np.float32),
        np.zeros((0, len(names)), np.float32),
        np.zeros((0, ROLLOUT_K + 1), np.int64),
    )
    lstm_pred = _predict_lstm(lstm, seq_test, ROLLOUT_K) if len(seq_test) else np.zeros((0, ROLLOUT_K + 1), dtype=int)
    window_pred = {h: window_models[h].predict(x_cur["test"]) if len(anchors["test"]) else np.zeros(0, dtype=int) for h in range(0, ROLLOUT_K + 1)}
    flat_pred = {h: flat_models[h].predict(flat["test"]) if len(anchors["test"]) else np.zeros(0, dtype=int) for h in range(0, ROLLOUT_K + 1)}
    persistence = {h: window_pred[0] for h in range(0, ROLLOUT_K + 1)}
    oracle = {h: y[("test", 0)] for h in range(0, ROLLOUT_K + 1)}
    named = {
        "logistic_window": window_pred,
        "logistic_flat10": flat_pred,
        "persistence": persistence,
        "oracle_persistence_unattainable": oracle,
        "lstm": {h: lstm_pred[:, h] for h in range(0, ROLLOUT_K + 1)},
    }
    block = {"seed": seed, "feature_set": kind_prefix, "horizons": {}, "onset": {}, "per_stage": {}}
    benign_now = y[("test", 0)] == 0 if len(anchors["test"]) else np.zeros(0, dtype=bool)
    for model_name, preds in named.items():
        block["horizons"][model_name] = {}
        block["per_stage"][model_name] = {}
        for horizon in EVAL_HORIZONS:
            scored = _horizon_block(y[("test", horizon)], preds[horizon], skip_labels)
            block["horizons"][model_name][horizon] = scored
            block["per_stage"][model_name][horizon] = scored["per_stage"]
        future_y = np.column_stack([y[("test", step)] for step in range(1, ROLLOUT_K + 1)]) if len(anchors["test"]) else np.zeros((0, ROLLOUT_K), dtype=int)
        future_p = np.column_stack([preds[step] for step in range(1, ROLLOUT_K + 1)]) if len(anchors["test"]) else np.zeros((0, ROLLOUT_K), dtype=int)
        if len(benign_now):
            block["onset"][model_name] = _onset(future_y[benign_now], future_p[benign_now])
        else:
            block["onset"][model_name] = {"precision": None, "recall": None, "fpr": None, "lead": None, "n": 0}
    if save and kind_prefix == "flow+packet":
        suffix = f"seed{seed}"
        save_logistic(MODELS_DIR / f"v3_logistic_window_{suffix}.joblib", window_models, scaler, clip, names, seed, "logistic_window", False)
        save_logistic(MODELS_DIR / f"v3_logistic_flat10_{suffix}.joblib", flat_models, scaler, clip, names, seed, "logistic_flat10", True)
        save_lstm(MODELS_DIR / f"v3_lstm_{suffix}.pt", lstm, scaler, clip, names, seed, "lstm")
    if save and kind_prefix == "flow":
        suffix = f"seed{seed}"
        save_logistic(MODELS_DIR / f"v3_logistic_window_flow_{suffix}.joblib", window_models, scaler, clip, names, seed, "logistic_window_flow", False)
        save_logistic(MODELS_DIR / f"v3_logistic_flat10_flow_{suffix}.joblib", flat_models, scaler, clip, names, seed, "logistic_flat10_flow", True)
        save_lstm(MODELS_DIR / f"v3_lstm_flow_{suffix}.pt", lstm, scaler, clip, names, seed, "lstm_flow")
    return block


def _loao_one(scaled, stages, frame, names, held_index: int, seed: int) -> dict:
    """Train without windows of one attack stage. Test on test windows of that stage."""
    held_name = V3_STAGES[held_index]
    banned = stages == held_index
    # Drop anchors whose input or target touches the held-out stage.
    def usable(split: str) -> np.ndarray:
        idx = sequence_anchors(frame, split, SEQ_LEN, ROLLOUT_K)
        keep = []
        for position in idx:
            position = int(position)
            span = stages[position - SEQ_LEN + 1:position + ROLLOUT_K + 1]
            if not np.any(span == held_index):
                keep.append(position)
        return np.asarray(keep, dtype=int)

    train_idx = usable("train")
    val_idx = usable("val")
    test_idx = sequence_anchors(frame, "test", SEQ_LEN, 0)
    # Horizon 0 on the held-out stage. History may contain that stage; training did not.
    test_idx = np.asarray([int(p) for p in test_idx if stages[int(p)] == held_index], dtype=int)
    if len(train_idx) == 0 or len(test_idx) == 0:
        return {
            "model_rows": [
                {
                    "model": model_name,
                    "held_out": held_name,
                    "recall": None,
                    "pred_share": {name: None for name in V3_STAGES},
                    "n": int(len(test_idx)),
                }
                for model_name in ("logistic_window", "logistic_flat10", "lstm")
            ],
            "n_train": int(len(train_idx)),
            "n_test": int(len(test_idx)),
        }
    y_train = stages[train_idx]
    window_model = _fit_logistic(scaled[train_idx], y_train, seed)
    flat_train = np.stack([scaled[int(p) - SEQ_LEN + 1:int(p) + 1].reshape(-1) for p in train_idx]).astype(np.float32)
    flat_model = _fit_logistic(flat_train, y_train, seed + 17)
    seq_train, nxt_train, ys_train = stack_sequences(scaled, stages, train_idx, SEQ_LEN, ROLLOUT_K)
    val_pack = None
    if len(val_idx):
        seq_val, _, y_val = stack_sequences(scaled, stages, val_idx, SEQ_LEN, ROLLOUT_K)
        val_pack = {"seq": seq_val, "y": y_val}
    lstm = fit_lstm(seq_train, nxt_train, ys_train, val_pack, seed)
    flat_test = np.stack([scaled[int(p) - SEQ_LEN + 1:int(p) + 1].reshape(-1) for p in test_idx]).astype(np.float32)
    seq_test = np.stack([scaled[int(p) - SEQ_LEN + 1:int(p) + 1] for p in test_idx]).astype(np.float32)
    preds = {
        "logistic_window": window_model.predict(scaled[test_idx]),
        "logistic_flat10": flat_model.predict(flat_test),
        "lstm": _predict_lstm(lstm, seq_test, 1)[:, 0],
    }
    rows = []
    for model_name, pred in preds.items():
        recall = float(np.mean(pred == held_index)) if len(pred) else None
        shares = {}
        for index, name in enumerate(V3_STAGES):
            shares[name] = float(np.mean(pred == index)) if len(pred) else None
        rows.append({"model": model_name, "held_out": held_name, "recall": recall, "pred_share": shares, "n": int(len(pred))})
    return {"model_rows": rows, "n_train": int(len(train_idx)), "n_test": int(len(test_idx))}


def _aggregate(seed_blocks: list[dict], feature_set: str) -> tuple[list, list, list]:
    metrics, onset, per_stage = [], [], []
    model_names = seed_blocks[0]["horizons"].keys()
    for model_name in model_names:
        for horizon in EVAL_HORIZONS:
            metrics.append({
                "model": model_name,
                "horizon": horizon,
                "source": BENCHMARK_NAME,
                "feature_set": feature_set,
                "f1": _stat([block["horizons"][model_name][horizon]["f1"] for block in seed_blocks]),
                "precision": _stat([block["horizons"][model_name][horizon]["precision"] for block in seed_blocks]),
                "recall": _stat([block["horizons"][model_name][horizon]["recall"] for block in seed_blocks]),
                "fpr": _stat([block["horizons"][model_name][horizon]["fpr"] for block in seed_blocks]),
            })
            for stage in V3_STAGES:
                per_stage.append({
                    "model": model_name,
                    "horizon": horizon,
                    "stage": stage,
                    "feature_set": feature_set,
                    "f1": _stat([block["per_stage"][model_name][horizon][stage]["f1"] for block in seed_blocks]),
                    "support": _stat([block["per_stage"][model_name][horizon][stage]["support"] for block in seed_blocks]),
                })
        onset.append({
            "model": model_name,
            "feature_set": feature_set,
            "precision": _stat([block["onset"][model_name]["precision"] for block in seed_blocks]),
            "recall": _stat([block["onset"][model_name]["recall"] for block in seed_blocks]),
            "fpr": _stat([block["onset"][model_name]["fpr"] for block in seed_blocks]),
            "lead_windows": _stat([block["onset"][model_name]["lead"] for block in seed_blocks]),
            "n": _stat([block["onset"][model_name]["n"] for block in seed_blocks]),
        })
    return metrics, onset, per_stage


def _aggregate_loao(rows: list[dict]) -> list[dict]:
    grouped = {}
    for row in rows:
        grouped.setdefault((row["model"], row["held_out"]), []).append(row)
    out = []
    for (model_name, held), items in sorted(grouped.items()):
        entry = {
            "model": model_name,
            "held_out": held,
            "recall": _stat([item["recall"] for item in items]),
            "n": _stat([item["n"] for item in items]),
        }
        for stage in V3_STAGES:
            entry[f"pred_{stage}"] = _stat([item["pred_share"][stage] for item in items])
        out.append(entry)
    return out


def _split_payload(frame) -> dict:
    def counts(split: str) -> dict:
        sub = frame[frame["split"] == split]
        return {stage: int((sub["stage"] == stage).sum()) for stage in V3_STAGES} | {"windows": int(len(sub))}

    return {
        "method": "attack_span_then_60_15_25",
        "rule": (
            "On a day with attack windows, windows before the first-to-last attack span are train, "
            "the span is 60/15/25 with purge gaps, and windows after the span are test. "
            "A day with no attack windows stays 60/15/25."
        ),
        "fractions": {"train": 0.60, "val": 0.15, "test": 0.25},
        "purge_windows": SEQ_LEN + ROLLOUT_K,
        "gap_ms": 10 * 60 * 1000,
        "seq_len": SEQ_LEN,
        "k": ROLLOUT_K,
        "f1_definition": "macro-F1 over proxy stages with test support, excluding classes marked n too small",
        "persistence": "repeats the logistic_window predicted current stage; oracle_persistence_unattainable repeats the true current stage",
        "n_too_small": [
            stage for stage in ("initial_access", "lateral_movement", "command_and_control")
            if int(((frame["split"] == "test") & (frame["stage"] == stage)).sum()) < 20
        ],
        "train": counts("train"),
        "val": counts("val"),
        "test": counts("test"),
        "purge": counts("purge"),
    }


def _print_step9(precheck, full, frame, metrics, onset, loao, ablation, verdict, cross_day=None, main_feature_set: str = "flow+packet") -> None:
    print("\n===== STEP 9 SUMMARY =====", flush=True)
    print("PRECHECK", flush=True)
    print(f"rows {precheck['rows']}", flush=True)
    print(f"utc_min {precheck['utc_min']}", flush=True)
    print(f"utc_max {precheck['utc_max']}", flush=True)
    print(f"date_span {precheck['date_span']}", flush=True)
    print(
        f"out_of_order_rows {precheck['out_of_order_rows']} pairs {precheck['order_pairs']} "
        f"fraction {precheck['out_of_order_fraction']:.8f}",
        flush=True,
    )
    print("attack_value_counts", flush=True)
    for name, count in precheck["attack_counts"]:
        print(f"  {name!r} {count}", flush=True)
    print("windows_per_stage_per_day", flush=True)
    for (day, stage), count in full.groupby(["day", "stage"], sort=True).size().items():
        print(f"  {day} {stage} {int(count)}", flush=True)
    print("windows_per_stage_per_split", flush=True)
    split_rows = []
    for split in ("train", "val", "test", "purge"):
        sub = frame[frame["split"] == split]
        cells = [split, str(len(sub))]
        for stage in V3_STAGES:
            cells.append(str(int((sub["stage"] == stage).sum())))
        split_rows.append(cells)
        print("  " + " ".join(f"{cells[0]}" if index == 0 else f"{V3_STAGES[index - 2] if index > 1 else 'n'}={cells[index]}" for index in range(len(cells))), flush=True)
    _print_table(["split", "n", *V3_STAGES], split_rows)
    print("test_macro_f1_and_fpr", flush=True)
    main = [row for row in metrics if row["feature_set"] == main_feature_set]
    _print_table(
        ["model", "horizon", "macro_f1", "fpr"],
        [[row["model"], str(row["horizon"]), _fmt(row["f1"]), _fmt(row["fpr"])] for row in main],
    )
    print("onset  lead_windows is signed: positive means the predicted start is earlier than the true start", flush=True)
    _print_table(
        ["model", "precision", "recall", "fpr", "lead_windows"],
        [[row["model"], _fmt(row["precision"]), _fmt(row["recall"]), _fmt(row["fpr"]), _fmt(row["lead_windows"])] for row in onset if row["feature_set"] == main_feature_set],
    )
    print("leave_one_attack_out  recall is the share of held-out test windows predicted as that stage", flush=True)
    _print_table(
        ["model", "held_out", "recall", "n"],
        [[row["model"], row["held_out"], _fmt(row["recall"]), _fmt(row["n"])] for row in loao],
    )
    print("ablation_macro_f1", flush=True)
    _print_table(
        ["model", "features", "horizon", "macro_f1", "fpr"],
        [[row["model"], row["feature_set"], str(row["horizon"]), _fmt(row["f1"]), _fmt(row["fpr"])] for row in ablation],
    )
    print("cross_day  attack-vs-benign rates and lateral_movement F1 at horizon 0", flush=True)
    _print_table(
        ["train_day", "test_day", "model", "precision", "recall", "fpr", "lateral_f1"],
        [[
            row["train_day"], row["test_day"], row["model"],
            _fmt(row["precision"]), _fmt(row["recall"]), _fmt(row["fpr"]), _fmt(row["lateral_movement_f1"]),
        ] for row in (cross_day or [])],
    )
    print(verdict[0], flush=True)
    print(verdict[1], flush=True)
    print("===== END STEP 9 =====", flush=True)


def train_v3(csv_path, window_s: int = 60, seeds: int = 5, min_attack_frac: float = 0.05) -> dict:
    seed_list = list(range(int(seeds)))
    full, precheck = load_windows(Path(csv_path), window_s=window_s, min_attack_frac=min_attack_frac)
    frame = modeling_frame(full)
    print("windows_per_stage_per_split", flush=True)
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
            f'WARNING: {stage} has {count} test windows, fewer than 20. '
            'Marking this class "n too small" and not reporting an F1 for it.',
            flush=True,
        )
    full_blocks = _train_feature_set(frame, list(FEATURES), seed_list, "flow+packet", True, small)
    flow_blocks = _train_feature_set(frame, list(FLOW_FEATURES), seed_list, "flow", True, small)
    full_metrics, full_onset, full_stage = _aggregate(full_blocks, "flow+packet")
    flow_metrics, flow_onset, flow_stage = _aggregate(flow_blocks, "flow")
    # Ablation compares the learned models only. Persistence and the oracle stay on the full feature set.
    learned = {"logistic_window", "logistic_flat10", "lstm"}
    ablation = [row for row in full_metrics + flow_metrics if row["model"] in learned]
    metrics = full_metrics
    onset = full_onset
    per_stage = [row for row in full_stage if row["feature_set"] == "flow+packet"]
    for row in per_stage + flow_stage:
        if row["stage"] in small:
            row["f1"] = "n too small"

    print("leave-one-attack-out", flush=True)
    raw_loao = []
    names = list(FEATURES)
    heavy = [name for name in HEAVY_FEATURES if name in names]
    raw = _window_matrix(frame, names)
    stages = _codes(frame)
    train_rows = frame.index[frame["split"] == "train"].to_numpy()
    clip, scaler, _ = fit_clip_scaler(raw[train_rows], names, heavy)
    scaled = transform_matrix(raw, names, clip, scaler)
    for held in (1, 2, 3):
        if V3_STAGES[held] in small:
            print(f"loao {V3_STAGES[held]} skipped: n too small", flush=True)
            continue
        for seed in seed_list:
            print(f"loao {V3_STAGES[held]} seed {seed}", flush=True)
            result = _loao_one(scaled, stages, frame, names, held, seed)
            raw_loao.extend(result["model_rows"])
    loao = _aggregate_loao(raw_loao)
    for stage in small:
        count = int(((frame["split"] == "test") & (frame["stage"] == stage)).sum())
        for model_name in ("logistic_window", "logistic_flat10", "lstm"):
            loao.append({
                "model": model_name,
                "held_out": stage,
                "recall": "n too small",
                "n": {"mean": count, "std": 0.0},
                **{f"pred_{name}": "n too small" for name in V3_STAGES},
            })
    print("cross-day lateral_movement", flush=True)
    cross_day = _cross_day(frame, seed_list)
    verdict = _verdict(metrics)
    day_counts = {
        f"{day}|{stage}": int(count)
        for (day, stage), count in full.groupby(["day", "stage"]).size().items()
    }
    payload = {
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
            {"source": BENCHMARK_NAME, "name": "coverage", "text": coverage_sentence(full)},
            {"source": BENCHMARK_NAME, "name": "dataset", "text": "Evaluation is single-dataset."},
            {"source": BENCHMARK_NAME, "name": "verdict", "text": " ".join(verdict)},
        ],
        "onset": onset,
        "loao": loao,
        "ablation": ablation,
        "per_stage": per_stage,
        "cross_day": cross_day,
        "seeds": seed_list,
        "window_s": int(window_s),
        "counts": {
            "flows": precheck["rows"],
            "windows": int(len(full)),
            "dropped_windows": int((full["stage"] == "dropped").sum()),
            "out_of_order_fraction": precheck["out_of_order_fraction"],
            "attack_counts": precheck["attack_counts"],
            "windows_by_day_stage": day_counts,
            "flow_onset_not_in_main_table": flow_onset,
            "flow_per_stage_not_in_main_table": flow_stage,
        },
    }
    path = MODELS_DIR / BENCHMARK_NAME
    path.write_text(json.dumps(_py(payload), indent=2), encoding="utf-8")
    print(f"wrote {path}", flush=True)
    _print_step9(precheck, full, frame, metrics, onset, loao, ablation, verdict, cross_day)
    return payload


def _cross_day(frame, seeds) -> list[dict]:
    """Train on one infiltration day and test on the other, then swap. Horizon 0 only."""
    rows = []
    for train_day, test_day in (("2018-02-28", "2018-03-01"), ("2018-03-01", "2018-02-28")):
        sub = frame[frame["day"].isin([train_day, test_day])].copy()
        sub = sub.sort_values(["day", "window_start_ms"]).reset_index(drop=True)
        sub["split"] = np.where(sub["day"].to_numpy() == train_day, "train", "test")
        blocks = _train_feature_set(sub, list(FEATURES), seeds, f"cross {train_day}->{test_day}", False)
        for model_name in ("logistic_window", "logistic_flat10", "lstm"):
            rows.append({
                "train_day": train_day,
                "test_day": test_day,
                "model": model_name,
                "precision": _stat([block["horizons"][model_name][0]["precision"] for block in blocks]),
                "recall": _stat([block["horizons"][model_name][0]["recall"] for block in blocks]),
                "fpr": _stat([block["horizons"][model_name][0]["fpr"] for block in blocks]),
                "lateral_movement_f1": _stat([
                    block["per_stage"][model_name][0]["lateral_movement"]["f1"] for block in blocks
                ]),
            })
    return rows
