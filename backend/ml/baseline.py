"""Logistic-regression baseline: features of window t -> stage at t+k (direct multi-horizon)."""
import json, sys
from pathlib import Path
import joblib, numpy as np, pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_fscore_support, confusion_matrix
from sklearn.preprocessing import StandardScaler
from .features import FEATURES
from .stages import STAGES

MODELS_DIR = Path(__file__).resolve().parent / "models"
HORIZONS = [0, 1, 3]        # 0 = detect current stage, 1/3 = forecast k windows ahead

def shifted(df: pd.DataFrame, k: int, features=None):
    """Pairs (X_t, y_{t+k}) built inside each episode only (no leakage across episodes)."""
    columns = list(FEATURES if features is None else features)
    xs, ys = [], []
    for _, g in df.sort_values(["episode_id", "window_idx"]).groupby("episode_id"):
        X, y = g[columns].to_numpy(), g["stage"].map(STAGES.index).to_numpy()
        if k >= len(g): continue
        xs.append(X[: len(g) - k]); ys.append(y[k:])
    return np.vstack(xs), np.concatenate(ys)

def metrics(y_true, y_pred):
    p, r, f, _ = precision_recall_fscore_support(y_true, y_pred, average="macro", zero_division=0)
    attack_t, attack_p = y_true > 0, y_pred > 0            # binary view: any attack stage
    tn = ((~attack_t) & (~attack_p)).sum(); fp = ((~attack_t) & attack_p).sum()
    return dict(f1=round(f, 4), precision=round(p, 4), recall=round(r, 4),
                fpr=round(float(fp / max(fp + tn, 1)), 4))

def train(df: pd.DataFrame, test_frac=0.25, seed=0, test_episodes=None, features=None):
    columns = list(FEATURES if features is None else features)
    if test_episodes is None:
        eps = np.array(df.episode_id.unique(), dtype=object); rng = np.random.default_rng(seed); rng.shuffle(eps)
        test_episodes = eps[: int(len(eps) * test_frac)]
    test_eps = set(test_episodes)
    tr, te = df[~df.episode_id.isin(test_eps)], df[df.episode_id.isin(test_eps)]
    scaler = StandardScaler().fit(tr[columns].to_numpy())
    models, bench = {}, []
    for k in HORIZONS:
        Xtr, ytr = shifted(tr, k, columns); Xte, yte = shifted(te, k, columns)
        m = LogisticRegression(max_iter=2000, class_weight="balanced").fit(scaler.transform(Xtr), ytr)
        models[k] = m
        bench.append(dict(model="logistic_regression", horizon=k, **metrics(yte, m.predict(scaler.transform(Xte)))))
    return dict(scaler=scaler, models=models, features=columns, stages=STAGES, horizons=HORIZONS), bench

if __name__ == "__main__":
    from .synth import make_windows
    src = sys.argv[1] if len(sys.argv) > 1 else None
    df = pd.read_csv(src) if src else make_windows()
    print("data:", "real " + src if src else "synthetic", df.shape)
    bundle, bench = train(df)
    MODELS_DIR.mkdir(exist_ok=True)
    joblib.dump(bundle, MODELS_DIR / "baseline.joblib")
    (MODELS_DIR / "benchmark.json").write_text(json.dumps(bench, indent=2))
    print(pd.DataFrame(bench).to_string(index=False))
