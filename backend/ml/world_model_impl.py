"""PyTorch LSTM world model for PREDICT-X window sequences.

forecast.py loads this module and calls load_world_model(models_dir).rollout(X, K).
The logistic baseline files are not read for training and are not overwritten.

Stage targets are the existing CIC label proxy in cicids.py. They are not MITRE stages.
"""
import json
import random
import sys
from pathlib import Path

import joblib
import numpy as np
import torch
import torch.nn.functional as F
from sklearn.preprocessing import StandardScaler
from torch import nn

from .baseline import MODELS_DIR, metrics
from .features import CIC_FEATURES
from .stages import STAGES

WEIGHTS_NAME = "world_model_cicids2018.pt"
SCALER_NAME = "world_model_scaler_cicids2018.joblib"
BENCHMARK_NAME = "benchmark_world_model_cicids2018.json"
LOGISTIC_BENCHMARK = "benchmark_cicids2018.json"
LOGISTIC_BUNDLE = "baseline_cicids2018.joblib"

SEED = 0
SEQ_LEN = 10
HORIZON_MAX = 3
EVAL_HORIZONS = (0, 1, 3)
HIDDEN = 64
EMBEDDING = 16
EPOCHS = 30
LR = 1e-3
WEIGHT_DECAY = 1e-4
BATCH_SIZE = 64


def set_seed(seed: int = SEED) -> None:
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


class WorldLSTM(nn.Module):
    """Encode 10 windows, classify the current stage, then roll the stage forward."""

    def __init__(self, n_features: int, n_stages: int, hidden: int = HIDDEN, embedding: int = EMBEDDING):
        super().__init__()
        self.n_stages = n_stages
        self.encoder = nn.LSTM(n_features, hidden, num_layers=1, batch_first=True)
        self.now = nn.Linear(hidden, n_stages)
        self.stage_emb = nn.Embedding(n_stages, embedding)
        self.dec_in = nn.Linear(embedding, hidden)
        self.decoder = nn.LSTMCell(hidden, hidden)
        self.future = nn.Linear(hidden, n_stages)

    def forward(self, x: torch.Tensor, steps: int):
        """x is [batch, seq, features]. Returns current logits and future logits [batch, steps, stages]."""
        _, (h, c) = self.encoder(x)
        h, c = h[-1], c[-1]
        now_logits = self.now(h)
        prev = torch.softmax(now_logits, dim=-1)
        futures = []
        for _ in range(steps):
            embedded = prev @ self.stage_emb.weight
            h, c = self.decoder(self.dec_in(embedded), (h, c))
            step = self.future(h)
            futures.append(step)
            prev = torch.softmax(step, dim=-1)
        return now_logits, torch.stack(futures, dim=1)


class LoadedWorldModel:
    """Inference wrapper. rollout matches the forecast.py hook."""

    def __init__(self, model: WorldLSTM, scaler: StandardScaler, seq_len: int, n_features: int, features=None):
        self.model = model.eval()
        self.scaler = scaler
        self.seq_len = seq_len
        self.features = None if features is None else [str(name) for name in features]
        self.n_features = len(self.features) if self.features is not None else int(n_features)

    def rollout(self, X_windows, K: int = 3) -> np.ndarray:
        """Observed windows [T, n_features] -> future stage probabilities [K, n_stages], in STAGES order."""
        X = np.asarray(X_windows, dtype=np.float64)
        if X.ndim != 2 or X.shape[1] != self.n_features:
            raise ValueError(f"rollout expected shape [T, {self.n_features}], got {X.shape}.")
        if K < 1:
            raise ValueError("K must be at least 1.")
        scaled = self.scaler.transform(X)
        if len(scaled) >= self.seq_len:
            seq = scaled[-self.seq_len:]
        else:
            pad = np.zeros((self.seq_len - len(scaled), scaled.shape[1]), dtype=np.float64)
            seq = np.vstack([pad, scaled])
        xt = torch.tensor(seq, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            _, future_logits = self.model(xt, int(K))
            probs = torch.softmax(future_logits[0], dim=-1).cpu().numpy()
        return np.asarray(probs, dtype=np.float64)


def _saved_feature_list(config: dict, scaler) -> list | None:
    """Feature names stored on the checkpoint or the scaler. Older files only store a width."""
    names = config.get("features")
    if names is None:
        names = getattr(scaler, "feature_columns_", None)
    if names is None:
        raw = getattr(scaler, "feature_names_in_", None)
        names = None if raw is None else list(raw)
    if names is None:
        return None
    return [str(name) for name in names]


def load_world_model(models_dir) -> LoadedWorldModel:
    root = Path(models_dir)
    weights = root / WEIGHTS_NAME
    scaler_path = root / SCALER_NAME
    if not weights.is_file() or not scaler_path.is_file():
        raise FileNotFoundError(f"World model files missing in {root}.")
    checkpoint = torch.load(weights, map_location="cpu", weights_only=False)
    config = checkpoint["config"]
    scaler = joblib.load(scaler_path)
    features = _saved_feature_list(config, scaler)
    n_features = len(features) if features is not None else int(config["n_features"])
    model = WorldLSTM(
        n_features=n_features,
        n_stages=config["n_stages"],
        hidden=config["hidden"],
        embedding=config["embedding"],
    )
    model.load_state_dict(checkpoint["state_dict"])
    return LoadedWorldModel(
        model, scaler, seq_len=config["seq_len"], n_features=n_features, features=features
    )


def _stage_index(frame) -> np.ndarray:
    return frame["stage"].map(STAGES.index).to_numpy(dtype=np.int64)


def build_sequences(frame, split: str, seq_len: int = SEQ_LEN, horizon: int = HORIZON_MAX, features=None):
    """Contiguous sequences that lie entirely inside one train session or one test session."""
    columns = list(CIC_FEATURES if features is None else features)
    sequences, current, future, endpoints = [], [], [], []
    part = frame[frame["split"] == split]
    for _, episode in part.groupby("episode_id", sort=False):
        episode = episode.sort_values("window_idx")
        values = episode[columns].to_numpy(dtype=np.float64)
        labels = _stage_index(episode)
        last = len(episode) - horizon - 1
        for end in range(seq_len - 1, last + 1):
            sequences.append(values[end - seq_len + 1:end + 1])
            current.append(labels[end])
            future.append(labels[end + 1:end + 1 + horizon])
            endpoints.append(values[end])
    if not sequences:
        raise RuntimeError(f"No {split} sequences of length {seq_len} with {horizon} future windows.")
    return (
        np.stack(sequences),
        np.asarray(current, dtype=np.int64),
        np.stack(future),
        np.stack(endpoints),
    )


def _class_weights(labels: np.ndarray) -> torch.Tensor:
    counts = np.bincount(labels, minlength=len(STAGES)).astype(np.float64)
    present = counts > 0
    weights = np.ones(len(STAGES), dtype=np.float64)
    weights[present] = counts.sum() / (present.sum() * counts[present])
    return torch.tensor(weights, dtype=torch.float32)


def _transition_facts(frame) -> dict:
    changes = 0
    adjacent = 0
    for _, episode in frame.groupby("episode_id", sort=False):
        labels = _stage_index(episode.sort_values("window_idx"))
        if len(labels) < 2:
            continue
        changes += int((labels[1:] != labels[:-1]).sum())
        adjacent += int(len(labels) - 1)
    return {
        "adjacent_window_pairs": adjacent,
        "stage_changes": changes,
        "change_rate": round(changes / adjacent, 4) if adjacent else None,
    }


def _score(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    return metrics(y_true, y_pred)


def _predict_split(model: WorldLSTM, sequences: np.ndarray, scaler: StandardScaler):
    scaled = scaler.transform(sequences.reshape(-1, sequences.shape[-1])).reshape(sequences.shape)
    xt = torch.tensor(scaled, dtype=torch.float32)
    model.eval()
    with torch.no_grad():
        now_logits, future_logits = model(xt, HORIZON_MAX)
    return now_logits.argmax(dim=1).cpu().numpy(), future_logits.argmax(dim=-1).cpu().numpy()


def _logistic_same_endpoints(endpoints: np.ndarray, current: np.ndarray, future: np.ndarray) -> dict:
    bundle = joblib.load(MODELS_DIR / LOGISTIC_BUNDLE)
    scaled = bundle["scaler"].transform(endpoints)
    scored = {}
    targets = {0: current, 1: future[:, 0], 3: future[:, 2]}
    for horizon, y_true in targets.items():
        pred = bundle["models"][horizon].predict(scaled)
        scored[str(horizon)] = _score(y_true, pred)
    return scored


def train_and_evaluate(data_dir: Path, window_s: int | None = None) -> dict:
    from .cicids import (
        LABEL_TO_STAGE,
        STAGE_NOTES,
        UNASSIGNED_STAGES,
        WINDOW_S,
        capture_paths,
        prepare_cicids,
        print_load_table,
    )

    if window_s is None:
        window_s = WINDOW_S
    set_seed(SEED)
    paths = capture_paths(data_dir)
    frame, file_stats, _ = prepare_cicids(paths, window_s=window_s)
    print_load_table(frame, file_stats)
    columns = list(CIC_FEATURES)
    train_x, train_y0, train_yf, _ = build_sequences(frame, "train", features=columns)
    test_x, test_y0, test_yf, test_endpoints = build_sequences(frame, "test", features=columns)

    scaler = StandardScaler().fit(frame.loc[frame["split"] == "train", columns].to_numpy(dtype=np.float64))
    scaler.feature_columns_ = list(columns)
    set_seed(SEED)
    model = WorldLSTM(n_features=len(columns), n_stages=len(STAGES))
    optimizer = torch.optim.Adam(model.parameters(), lr=LR, weight_decay=WEIGHT_DECAY)
    weights = _class_weights(np.concatenate([train_y0, train_yf.reshape(-1)]))
    order_rng = np.random.default_rng(SEED)
    losses = []
    model.train()
    for epoch in range(EPOCHS):
        permutation = order_rng.permutation(len(train_x))
        total = 0.0
        seen = 0
        for start in range(0, len(permutation), BATCH_SIZE):
            batch = permutation[start:start + BATCH_SIZE]
            raw = train_x[batch]
            scaled = scaler.transform(raw.reshape(-1, raw.shape[-1])).reshape(raw.shape)
            xb = torch.tensor(scaled, dtype=torch.float32)
            y0 = torch.tensor(train_y0[batch], dtype=torch.long)
            yf = torch.tensor(train_yf[batch], dtype=torch.long)
            optimizer.zero_grad()
            now_logits, future_logits = model(xb, HORIZON_MAX)
            loss = F.cross_entropy(now_logits, y0, weight=weights)
            for step in range(HORIZON_MAX):
                loss = loss + F.cross_entropy(future_logits[:, step], yf[:, step], weight=weights)
            loss = loss / (1 + HORIZON_MAX)
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total += float(loss.item()) * len(batch)
            seen += len(batch)
        epoch_loss = total / seen
        losses.append(round(epoch_loss, 6))
        if epoch == 0 or epoch + 1 == EPOCHS or (epoch + 1) % 5 == 0:
            print(f"epoch {epoch + 1}/{EPOCHS} loss {epoch_loss:.4f}")

    pred0, pred_future = _predict_split(model, test_x, scaler)
    lstm_metrics = {
        "0": _score(test_y0, pred0),
        "1": _score(test_yf[:, 0], pred_future[:, 0]),
        "3": _score(test_yf[:, 2], pred_future[:, 2]),
    }
    published = json.loads((MODELS_DIR / LOGISTIC_BENCHMARK).read_text(encoding="utf-8"))
    published_by_h = {str(row["horizon"]): {k: row[k] for k in ("f1", "precision", "recall", "fpr")}
                      for row in published["results"]}
    same_endpoints = _logistic_same_endpoints(test_endpoints, test_y0, test_yf)
    comparison = []
    for horizon in EVAL_HORIZONS:
        key = str(horizon)
        lstm_f1 = lstm_metrics[key]["f1"]
        published_f1 = published_by_h[key]["f1"]
        same_f1 = same_endpoints[key]["f1"]
        comparison.append({
            "horizon": horizon,
            "lstm": lstm_metrics[key],
            "logistic_published": published_by_h[key],
            "logistic_same_test_endpoints": same_endpoints[key],
            "lstm_f1_minus_published": round(lstm_f1 - published_f1, 4),
            "lstm_f1_minus_same_endpoints": round(lstm_f1 - same_f1, 4),
        })

    config = {
        "n_features": len(columns),
        "features": list(columns),
        "n_stages": len(STAGES),
        "hidden": HIDDEN,
        "embedding": EMBEDDING,
        "seq_len": SEQ_LEN,
        "seed": SEED,
    }
    MODELS_DIR.mkdir(exist_ok=True)
    weights_path = MODELS_DIR / WEIGHTS_NAME
    scaler_path = MODELS_DIR / SCALER_NAME
    report_path = MODELS_DIR / BENCHMARK_NAME
    torch.save({"state_dict": model.state_dict(), "config": config}, weights_path)
    joblib.dump(scaler, scaler_path)

    train_part = frame[frame["split"] == "train"]
    test_part = frame[frame["split"] == "test"]
    report = {
        "dataset": "CIC-IDS-2018",
        "identifier": "real CIC-IDS-2018 LSTM world model",
        "model": "pytorch_lstm",
        "compared_with": LOGISTIC_BENCHMARK,
        "sequence_length": SEQ_LEN,
        "window_seconds": int(window_s),
        "n_train_sequences": int(len(train_x)),
        "n_test_sequences": int(len(test_x)),
        "architecture": {
            "encoder": f"LSTM(input={len(columns)}, hidden={HIDDEN}, layers=1)",
            "current_stage_head": f"Linear({HIDDEN}, {len(STAGES)})",
            "rollout": (
                f"LSTMCell({HIDDEN}) fed by a soft distribution over {len(STAGES)} stages "
                f"embedded to {EMBEDDING} dimensions"
            ),
            "features": list(columns),
            "stages": list(STAGES),
        },
        "training": {
            "seed": SEED,
            "epochs": EPOCHS,
            "lr": LR,
            "weight_decay": WEIGHT_DECAY,
            "batch_size": BATCH_SIZE,
            "loss": "mean of class-weighted cross-entropy on the current stage and the next 3 stages",
            "first_epoch_loss": losses[0],
            "last_epoch_loss": losses[-1],
            "epoch_loss": losses,
            "normalization": "StandardScaler fit only on training-session windows",
            "sequences": (
                "Each sequence and its future labels stay inside one session. "
                "Train sequences use only split=train. Test sequences use only split=test."
            ),
        },
        "split": {
            "method": "same future-session holdout as cicids.py",
            "n_train_windows": int(len(train_part)),
            "n_test_windows": int(len(test_part)),
            "train_time": [str(train_part.window_start.min()), str(train_part.window_start.max())],
            "test_time": [str(test_part.window_start.min()), str(test_part.window_start.max())],
        },
        "label_to_stage": {
            label: {"stage": stage, "note": STAGE_NOTES[label]}
            for label, stage in LABEL_TO_STAGE.items()
        },
        "stages_not_assigned": list(UNASSIGNED_STAGES),
        "stage_mapping_disclaimer": (
            "CIC-IDS-2018 Label values are attack-class names. They are not MITRE ATT&CK "
            "tactics and they are not PREDICT-X stages. The mapping is the cicids.py proxy."
        ),
        "persistence": {
            "test_next_window_same_stage": round(float((test_yf[:, 0] == test_y0).mean()), 4),
            "test_plus_3_same_stage": round(float((test_yf[:, 2] == test_y0).mean()), 4),
            "train_sessions": _transition_facts(train_part),
            "test_sessions": _transition_facts(test_part),
        },
        "results": [{"horizon": h, **lstm_metrics[str(h)]} for h in EVAL_HORIZONS],
        "comparison": comparison,
        "logistic_baseline_unchanged": [LOGISTIC_BUNDLE, LOGISTIC_BENCHMARK, "baseline.joblib", "benchmark.json"],
        "f1_comparison_note": (
            "Macro F1 versus the published logistic benchmark: "
            + ", ".join(f"h{row['horizon']} {row['lstm_f1_minus_published']:+.4f}" for row in comparison)
            + ". Same-endpoint logistic rescore: "
            + ", ".join(f"h{row['horizon']} {row['lstm_f1_minus_same_endpoints']:+.4f}" for row in comparison)
            + ". A positive number means the LSTM F1 is higher on that horizon. It is not an overall claim."
        ),
    }
    test_episode = frame[frame["split"] == "test"].sort_values(["episode_id", "window_idx"])
    first_id = test_episode["episode_id"].iloc[0]
    observed = test_episode.loc[test_episode["episode_id"] == first_id, columns].to_numpy(dtype=np.float64)
    rolled = load_world_model(MODELS_DIR).rollout(observed, K=3)
    if rolled.shape != (3, len(STAGES)) or not np.allclose(rolled.sum(axis=1), 1.0, atol=1e-5):
        raise RuntimeError(f"Saved model rollout failed: shape {rolled.shape}, sums {rolled.sum(axis=1)}.")
    report["rollout_check"] = {
        "windows": int(len(observed)),
        "shape": list(rolled.shape),
        "row_sums": [round(float(v), 6) for v in rolled.sum(axis=1)],
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["wrote"] = [str(weights_path), str(scaler_path), str(report_path)]
    return report


def _print_report(report: dict) -> None:
    print("train_sequences", report["n_train_sequences"], "test_sequences", report["n_test_sequences"])
    print("loss", report["training"]["first_epoch_loss"], "->", report["training"]["last_epoch_loss"])
    print("persistence_t+1", report["persistence"]["test_next_window_same_stage"],
          "persistence_t+3", report["persistence"]["test_plus_3_same_stage"])
    print("stage_changes_test", report["persistence"]["test_sessions"])
    for row in report["comparison"]:
        print(
            "h", row["horizon"],
            "lstm_f1", row["lstm"]["f1"],
            "published_f1", row["logistic_published"]["f1"],
            "same_endpoint_f1", row["logistic_same_test_endpoints"]["f1"],
            "fpr", row["lstm"]["fpr"],
        )
    for path in report["wrote"]:
        print("wrote", path)


if __name__ == "__main__":
    from .cicids import resolve_data_dir
    directory = Path(sys.argv[1]) if len(sys.argv) > 1 else resolve_data_dir()
    summary = train_and_evaluate(directory)
    print("rollout_ok", summary["rollout_check"])
    _print_report(summary)
