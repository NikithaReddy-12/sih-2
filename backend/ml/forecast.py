"""Forecast service: windows -> stage timeline (observed + K future).

Two modes, never mixed:
- synthetic: baseline.joblib for the current stage and for the logistic future.
- cicids2018: baseline_cicids2018.joblib for the current stage, and the CIC LSTM
  rollout for every future step. The LSTM applies world_model_scaler_cicids2018.joblib.
"""
import json
from pathlib import Path
import joblib, numpy as np, pandas as pd
from .baseline import MODELS_DIR
from .cicids import LABEL_TO_STAGE, UNASSIGNED_STAGES
from .explain import explain_linear
from .stages import STAGES, describe

SYNTHETIC = "synthetic"
CICIDS = "cicids2018"
NETFLOW_V3_HOST = "netflow_v3_host"
CIC_BASELINE_NAME = "baseline_cicids2018.joblib"
# Stages this capture subset can support. The other STAGES are not predicted.
CIC_SUPPORTED_STAGES = list(dict.fromkeys(LABEL_TO_STAGE.values()))

_cache = {}


def _load_bundle(name: str, cache_key: str):
    if cache_key not in _cache:
        path = MODELS_DIR / name
        _cache[cache_key] = joblib.load(path) if path.is_file() else None
    return _cache[cache_key]


def _synthetic_baseline():
    return _load_bundle("baseline.joblib", "synthetic")


def _cic_baseline():
    return _load_bundle(CIC_BASELINE_NAME, "cic")


def _cic_world():
    if "cic_world" not in _cache:
        try:
            from .world_model_impl import load_world_model
            _cache["cic_world"] = load_world_model(MODELS_DIR)
        except Exception:
            _cache["cic_world"] = None
    return _cache["cic_world"]


def model_info():
    synthetic_ok = _synthetic_baseline() is not None
    cic_base_ok = _cic_baseline() is not None
    cic_world_ok = _cic_world() is not None
    cic_ready = cic_base_ok and cic_world_ok
    return {
        "synthetic_baseline_loaded": synthetic_ok,
        "cic_baseline_loaded": cic_base_ok,
        "cic_world_model_loaded": cic_world_ok,
        "active_mode": CICIDS if cic_ready else SYNTHETIC,
        "demo_mode": SYNTHETIC,
        "host_lstm": "v3_host_lstm_seed0.pt",
        "modes": {
            SYNTHETIC: {
                "route": "/api/forecast/demo",
                "available": synthetic_ok,
                "observed_model": "baseline.joblib",
                "future_model": "logistic_regression",
            },
            CICIDS: {
                "route": "/api/forecast/cicids",
                "available": cic_ready,
                "observed_model": CIC_BASELINE_NAME,
                "future_model": "world_model_cicids2018.pt",
                "lstm_scaler": "world_model_scaler_cicids2018.joblib",
                "supported_stages": list(CIC_SUPPORTED_STAGES),
                "not_predicted_from_this_subset": list(UNASSIGNED_STAGES),
                "note": (
                    "CIC-IDS-2018 labels are attack-class names, not MITRE stages. "
                    "This subset supports benign, initial_access, lateral_movement, and command_and_control. "
                    "Bot is a proxy for command_and_control. "
                    "Reconnaissance and exfiltration are not predicted. "
                    "The saved CIC feature list omits uniq_src_ips and uniq_dst_ips."
                ),
            },
            NETFLOW_V3_HOST: {
                "route": "/api/forecast/netflow-v3-host",
                "available": (MODELS_DIR / "v3_host_lstm_seed0.pt").is_file(),
                "future_model": "v3_host_lstm_seed0.pt",
                "seed": 0,
                "supported_stages": ["benign", "initial_access", "lateral_movement", "command_and_control"],
                "not_predicted_from_this_subset": ["reconnaissance", "exfiltration"],
                "mitre": [
                    {"stage": "initial_access", "mitre_id": "TA0001"},
                    {"stage": "lateral_movement", "mitre_id": "TA0008"},
                    {"stage": "command_and_control", "mitre_id": "TA0011"},
                ],
                "note": "Host LSTM seed 0. attack_prob on each network window is the max over hosts of 1 - P(benign).",
            },
        },
    }


def _attack_probability(distribution, classes) -> float:
    """1 - P(benign). Class index 0 is benign. A model without that class counts as 1."""
    labels = [int(label) for label in classes]
    benign = float(distribution[labels.index(0)]) if 0 in labels else 0.0
    return round(min(1.0, max(0.0, 1.0 - benign)), 3)


def _benchmark_files():
    """benchmark*.json sitting directly in ml/models. archive/ is not read."""
    return sorted(
        path for path in MODELS_DIR.iterdir()
        if path.is_file() and path.name.startswith("benchmark") and path.suffix == ".json"
    )


def benchmark():
    """Every top-level benchmark JSON under ml/models, under one stable shape."""
    files = _benchmark_files()
    if not files:
        return {
            "models": [],
            "horizons": [],
            "metrics": [],
            "split": {},
            "notes": [{"source": "", "name": "status", "text": "No benchmark yet"}],
        }
    models, horizons, metrics, notes = [], [], [], []
    split = {}
    extra = {}
    passthrough = ("onset", "loao", "ablation", "per_stage", "seeds", "window_s", "counts", "cross_day", "granularity")
    note_keys = ("identifier", "stage_mapping_disclaimer", "window_label_rule", "f1_comparison_note")
    for path in files:
        payload = json.loads(path.read_text(encoding="utf-8"))
        source = path.name
        if isinstance(payload, dict) and isinstance(payload.get("metrics"), list):
            declared = payload.get("models") or []
            for item in declared:
                name = item.get("name") if isinstance(item, dict) else str(item)
                if not any(row["name"] == name and row["source"] == source for row in models):
                    models.append({"name": name, "source": source})
            for row in payload["metrics"]:
                if not isinstance(row, dict) or "horizon" not in row:
                    continue
                name = str(row.get("model") or source)
                if not any(item["name"] == name and item["source"] == source for item in models):
                    models.append({"name": name, "source": source})
                horizon = row["horizon"]
                if horizon not in horizons:
                    horizons.append(horizon)
                metric = {"model": name, "horizon": horizon, "source": source}
                for key in ("f1", "precision", "recall", "fpr"):
                    if key in row:
                        metric[key] = row[key]
                metrics.append(metric)
            if isinstance(payload.get("split"), dict):
                split[source] = payload["split"]
            for note in payload.get("notes") or []:
                if isinstance(note, str):
                    notes.append({"source": source, "name": "note", "text": note})
                elif isinstance(note, dict) and note.get("text"):
                    notes.append({
                        "source": str(note.get("source") or source),
                        "name": str(note.get("name") or "note"),
                        "text": str(note["text"]),
                    })
            for key in passthrough:
                if key not in payload:
                    continue
                value = payload[key]
                if key not in extra:
                    extra[key] = value
                elif isinstance(extra[key], list) and isinstance(value, list):
                    extra[key] = list(extra[key]) + list(value)
            continue
        rows = payload if isinstance(payload, list) else list(payload.get("results") or [])
        model_name = None if isinstance(payload, list) else payload.get("model")
        if isinstance(payload, dict):
            label = str(model_name or payload.get("identifier") or source)
            models.append({"name": label, "source": source})
            if isinstance(payload.get("split"), dict):
                split[source] = payload["split"]
            for key in note_keys:
                if payload.get(key):
                    notes.append({"source": source, "name": key, "text": str(payload[key])})
            if payload.get("stages_not_assigned"):
                notes.append({
                    "source": source,
                    "name": "stages_not_assigned",
                    "text": ", ".join(str(item) for item in payload["stages_not_assigned"]),
                })
        for row in rows:
            if not isinstance(row, dict) or "horizon" not in row:
                continue
            name = str(row.get("model") or model_name or source)
            if isinstance(payload, list) and not any(item["name"] == name and item["source"] == source for item in models):
                models.append({"name": name, "source": source})
            horizon = row["horizon"]
            if horizon not in horizons:
                horizons.append(horizon)
            metric = {"model": name, "horizon": horizon, "source": source}
            for key in ("f1", "precision", "recall", "fpr"):
                if key in row:
                    metric[key] = row[key]
            metrics.append(metric)
    body = {
        "models": models,
        "horizons": sorted(horizons, key=lambda value: (isinstance(value, str), value)),
        "metrics": metrics,
        "split": split,
        "notes": notes,
    }
    body.update(extra)
    return body


def _restrict_observed(proba, model, stages: list) -> list:
    classes = list(model.classes_)
    supported = set(CIC_SUPPORTED_STAGES)
    restricted = []
    for row, stage in enumerate(stages):
        if stage in supported:
            restricted.append(stage)
            continue
        best_name, best_prob = "benign", -1.0
        for column, label in enumerate(classes):
            name = STAGES[int(label)]
            if name in supported and float(proba[row][column]) > best_prob:
                best_name, best_prob = name, float(proba[row][column])
        restricted.append(best_name)
    return restricted


def _supported_stage(pk: np.ndarray) -> tuple:
    """Argmax inside the stages this CIC subset actually labels. Raw LSTM probability is kept."""
    idxs = [STAGES.index(stage) for stage in CIC_SUPPORTED_STAGES]
    pk = np.asarray(pk, dtype=float)
    choice = idxs[int(np.argmax(pk[idxs]))]
    return choice, float(pk[choice])


def _score_columns(bundle) -> list:
    """Column names stored in the saved baseline bundle."""
    saved = bundle.get("features")
    if not saved:
        raise RuntimeError("Saved baseline bundle has no feature list.")
    return [str(name) for name in saved]


def _world_columns(world, logistic_columns: list) -> list:
    """Column names stored on the LSTM artifact. Older checkpoints only store a width."""
    names = getattr(world, "features", None)
    width = getattr(world, "n_features", None)
    if names:
        columns = [str(name) for name in names]
    elif width is None or int(width) == len(logistic_columns):
        columns = list(logistic_columns)
    else:
        raise RuntimeError(
            "World model has no saved feature list and its input width does not match the baseline."
        )
    if width is not None and len(columns) != int(width):
        raise RuntimeError(
            f"World model feature list has length {len(columns)}, expected {int(width)}."
        )
    return columns


def _observed(bundle, arr: np.ndarray):
    scaled = bundle["scaler"].transform(arr)
    model = bundle["models"][0]
    proba = model.predict_proba(scaled)
    classes = list(model.classes_)
    stages = [STAGES[classes[i]] for i in proba.argmax(1)]
    return scaled, proba, model, stages


def forecast(X: pd.DataFrame, times: list, K: int = 3, history: int = 12, mode: str = SYNTHETIC):
    if mode not in (SYNTHETIC, CICIDS):
        raise ValueError(f"Unknown forecast mode {mode!r}.")
    if mode == CICIDS:
        bundle = _cic_baseline()
        world = _cic_world()
        if bundle is None or world is None:
            raise RuntimeError(
                "CIC-IDS-2018 forecast requires baseline_cicids2018.joblib, "
                "world_model_cicids2018.pt, and world_model_scaler_cicids2018.joblib. "
                "The synthetic baseline is not used as a fallback."
            )
        source = CICIDS
    else:
        bundle = _synthetic_baseline()
        world = None
        if bundle is None:
            raise RuntimeError("baseline.joblib missing. Run: python -m ml.baseline")
        source = "logistic_regression"

    columns = _score_columns(bundle)
    world_columns = _world_columns(world, columns) if world is not None else columns
    needed = list(dict.fromkeys([*columns, *world_columns]))
    missing = [name for name in needed if name not in X.columns]
    if missing:
        raise ValueError(f"Forecast frame is missing columns: {missing}.")
    frame = X
    arr = frame[columns].astype(float).to_numpy()
    scaled, proba, current_model, observed = _observed(bundle, arr)
    if mode == CICIDS:
        observed = _restrict_observed(proba, current_model, observed)

    timeline = []
    observed_classes = list(current_model.classes_)
    start = max(0, len(arr) - history)
    for i in range(start, len(arr)):
        timeline.append(dict(
            t=str(times[i]),
            observed=True,
            prob=round(float(proba[i].max()), 3),
            attack_prob=_attack_probability(proba[i], observed_classes),
            **describe(observed[i]),
        ))

    step = None
    if len(times) > 1 and not isinstance(times[-1], (int, np.integer)):
        step = pd.Timestamp(times[-1]) - pd.Timestamp(times[-2])
    explanation = []
    method = None
    if world is not None:
        future_probs = np.asarray(world.rollout(frame[world_columns].astype(float).to_numpy(), K))
        if future_probs.shape != (K, len(STAGES)):
            raise RuntimeError(f"LSTM rollout returned shape {future_probs.shape}, expected {(K, len(STAGES))}.")
    else:
        future_probs = None

    for k in range(1, K + 1):
        if future_probs is not None:
            choice, prob = _supported_stage(future_probs[k - 1])
            stage = STAGES[choice]
            attack_prob = _attack_probability(future_probs[k - 1], range(len(STAGES)))
        else:
            hk = min(bundle["horizons"], key=lambda h: abs(h - k) if h > 0 else 99)
            model = bundle["models"][hk]
            pk = model.predict_proba(scaled[-1:])[0]
            classes = list(model.classes_)
            choice = classes[int(np.argmax(pk))]
            stage = STAGES[choice]
            prob = float(np.max(pk))
            attack_prob = _attack_probability(pk, classes)
        when = str(pd.Timestamp(times[-1]) + step * k) if step is not None else f"+{k}"
        timeline.append(dict(
            t=when, observed=False, prob=round(prob, 3), attack_prob=attack_prob, **describe(stage),
        ))
        if k == 1 and source == "logistic_regression":
            explanation = explain_linear(bundle, arr[-1], 1, choice)
            method = "linear"
        # The LSTM has no attention weights. Its future explanation stays empty.

    future = [entry for entry in timeline if not entry["observed"]]
    risk = max((entry["attack_prob"] for entry in future), default=0.0)
    observed_attack_probability = None
    if mode == CICIDS:
        observed_attack = [
            round(float(proba[i].max()), 3) for i in range(len(arr)) if observed[i] != "benign"
        ]
        observed_attack_probability = max(observed_attack) if observed_attack else None
    benign_index = list(current_model.classes_).index(0) if 0 in list(current_model.classes_) else None
    flagged = []
    for i in range(len(arr)):
        if observed[i] == "benign":
            continue
        score = 1.0 if benign_index is None else float(1 - proba[i][benign_index])
        flagged.append(dict(
            t=str(times[i]),
            stage=observed[i],
            score=round(score, 3),
            top_features=explain_linear(bundle, arr[i], 0, STAGES.index(observed[i]), 3),
        ))
    return dict(
        model=source,
        horizon_k=K,
        windows=len(arr),
        overall_risk=round(risk, 3),
        observed_attack_probability=observed_attack_probability,
        timeline=timeline,
        explanation=explanation,
        method=method,
        flagged_windows=flagged[-20:],
        next_action=next((entry["action"] for entry in future if entry["action"]), None),
        supported_stages=list(CIC_SUPPORTED_STAGES) if mode == CICIDS else list(STAGES),
    )
