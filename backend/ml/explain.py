"""Per-window explanation for the logistic regression.
For a linear model on standardised inputs, SHAP's LinearExplainer value for feature j
is coef[class, j] * x_scaled[j], so it is computed exactly here with no extra dependency.
Hook for Member 1's neural model: add `explain_attention` when the model exposes weights."""
import numpy as np

def explain_linear(bundle, x_row: np.ndarray, horizon: int, class_idx: int, top=5):
    xs = bundle["scaler"].transform(x_row.reshape(1, -1))[0]
    model = bundle["models"][horizon]
    ci = list(model.classes_).index(class_idx)
    contrib = model.coef_[ci] * xs
    order = np.argsort(-np.abs(contrib))[:top]
    return [dict(name=bundle["features"][j], shap=round(float(contrib[j]), 3),
                 value=round(float(x_row[j]), 3)) for j in order]
