"""Synthetic windowed data with kill-chain episodes. Lets Member 2 build and test
everything before Member 1's CIC-IDS/CTU-13 windows exist. Same columns as the real data."""
import numpy as np
import pandas as pd
from .stages import STAGES
from .features import FEATURES

# mean feature signature per stage (order = FEATURES)
_SIG = {
# Appended values: init fwd/bwd window bytes, PSH/ACK/FIN/URG ratios,
# log mean Flow IAT Max, log1p of mean packet-length variance.
 "benign":              [40, 8, 6, 6, 6.5, 7, .05, .02, 12, 8, 10, 9, 8000, 6000, .20, .75, .30, .01, 10.5, 5.994],
 "reconnaissance":      [180, 5, 2, 1, 4, 3, .70, .35, 220, 6, 2, 6, 1024, 512, .15, .40, .55, .02, 7.0, 4.394],
 "initial_access":      [70, 9, 9, 5, 7.5, 6.5, .30, .15, 8, 3, 3, 7, 65535, 8192, .45, .70, .20, .04, 8.5, 7.824],
 "lateral_movement":    [90, 8.5, 8, 8, 7.5, 7.5, .20, .08, 20, 25, 4, 7.5, 16384, 16384, .55, .85, .15, .02, 9.0, 7.496],
 "command_and_control": [30, 10, 4, 4, 5.5, 5.5, .05, .02, 3, 2, 2, 12, 4096, 2048, .25, .90, .10, .01, 13.5, 5.707],
 "exfiltration":        [45, 11, 40, 3, 11, 5, .05, .02, 4, 2, 2, 5, 8192, 65535, .35, .75, .30, .01, 6.5, 8.987],
}

def make_windows(n_episodes=300, seed=7, noise=0.35) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    chain = STAGES[1:]
    for ep in range(n_episodes):
        seq = ["benign"] * rng.integers(3, 8)
        for s in chain:
            if rng.random() < 0.9:                          # some attacks skip stages
                seq += [s] * rng.integers(2, 6)
                if rng.random() < .3: seq += ["benign"] * rng.integers(1, 3)   # slow / stealthy gaps
        seq += ["benign"] * rng.integers(2, 6)
        for i, s in enumerate(seq):
            base = np.array(_SIG[s], float)
            x = base * (1 + rng.normal(0, noise, len(base)))
            x = np.clip(x, 0, None)
            rows.append([f"ep{ep}", i, *x, s])
    return pd.DataFrame(rows, columns=["episode_id", "window_idx", *FEATURES, "stage"])
