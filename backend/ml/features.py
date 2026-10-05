"""Window features. FEATURES is the contract with Member 1's pipeline:
one row per time window, these columns, plus `episode_id`, `window_idx`, `stage`.
`flows_to_windows` is a simple stand-in that Member 1's pipeline can replace."""
import numpy as np
import pandas as pd

FEATURES = ["n_flows", "log_mean_duration", "mean_fwd_pkts", "mean_bwd_pkts",
            "log_mean_fwd_bytes", "log_mean_bwd_bytes", "syn_ratio", "rst_ratio",
            "uniq_dst_ports", "uniq_dst_ips", "uniq_src_ips", "log_mean_iat",
            "mean_init_fwd_win_byts", "mean_init_bwd_win_byts",
            "psh_ratio", "ack_ratio", "fin_ratio", "urg_ratio",
            "log_mean_flow_iat_max", "log_mean_pkt_len_var"]
# These two stay in the synthetic vector. CIC-IDS-2018 mode omits them: the ML CSV has no IP columns.
IP_FEATURES = ("uniq_src_ips", "uniq_dst_ips")
CIC_FEATURES = [name for name in FEATURES if name not in IP_FEATURES]

# tolerant column matching for CIC-IDS-2017/2018 exports
_ALIASES = {
    "timestamp": ["timestamp"], "src_ip": ["src ip", "source ip"], "dst_ip": ["dst ip", "destination ip"],
    "dst_port": ["dst port", "destination port"], "duration": ["flow duration"],
    "fwd_pkts": ["tot fwd pkts", "total fwd packets"], "bwd_pkts": ["tot bwd pkts", "total backward packets"],
    "fwd_bytes": ["totlen fwd pkts", "total length of fwd packets"],
    "bwd_bytes": ["totlen bwd pkts", "total length of bwd packets"],
    "syn": ["syn flag cnt", "syn flag count"], "rst": ["rst flag cnt", "rst flag count"],
    "iatm": ["flow iat mean"],
    "init_fwd_win": ["init fwd win byts", "init_win_bytes_forward"],
    "init_bwd_win": ["init bwd win byts", "init_win_bytes_backward"],
    "psh": ["psh flag cnt", "psh flag count"],
    "ack": ["ack flag cnt", "ack flag count"],
    "fin": ["fin flag cnt", "fin flag count"],
    "urg": ["urg flag cnt", "urg flag count"],
    "iat_max": ["flow iat max"],
    "pkt_len_var": ["pkt len var", "packet length variance"],
}

def _norm(df: pd.DataFrame) -> pd.DataFrame:
    low = {c.strip().lower(): c for c in df.columns}
    out = pd.DataFrame(index=df.index)
    for key, names in _ALIASES.items():
        col = next((low[n] for n in names if n in low), None)
        if col is not None:
            out[key] = df[col]
    return out

def flows_to_windows(df: pd.DataFrame, window_s: int = 60):
    """Raw flow CSV -> (feature DataFrame, window start times)."""
    f = _norm(df)
    numeric = ["duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "syn", "rst", "iatm", "dst_port",
               "init_fwd_win", "init_bwd_win", "psh", "ack", "fin", "urg", "iat_max", "pkt_len_var"]
    for c in numeric:
        f[c] = pd.to_numeric(f.get(c, 0), errors="coerce") if c in f else 0.0
    f = f.replace([np.inf, -np.inf], np.nan).fillna(0)
    if "timestamp" in f:
        ts = pd.to_datetime(f["timestamp"], errors="coerce", dayfirst=False)
        if ts.notna().any():
            f["win"] = ts.dt.floor(f"{window_s}s")
            f = f[ts.notna()]
    if "win" not in f:
        f["win"] = pd.RangeIndex(len(f)) // 100          # no timestamps: 100 flows per window
    for c in ["src_ip", "dst_ip"]:
        if c not in f: f[c] = "na"
    rows, starts = [], []
    for w, g in f.groupby("win", sort=True):
        n = len(g)
        rows.append([n, np.log1p(g.duration.mean()), g.fwd_pkts.mean(), g.bwd_pkts.mean(),
                     np.log1p(g.fwd_bytes.mean()), np.log1p(g.bwd_bytes.mean()),
                     (g.syn > 0).mean(), (g.rst > 0).mean(), g.dst_port.nunique(),
                     g.dst_ip.nunique(), g.src_ip.nunique(), np.log1p(g.iatm.mean()),
                     g.init_fwd_win.mean(), g.init_bwd_win.mean(),
                     (g.psh > 0).mean(), (g.ack > 0).mean(), (g.fin > 0).mean(), (g.urg > 0).mean(),
                     np.log1p(g.iat_max.mean()), np.log1p(g.pkt_len_var.mean())])
        starts.append(w)
    return pd.DataFrame(rows, columns=FEATURES), list(starts)
