"""Window features for the NetFlow-V3 world model.

FLOW_FEATURES describe the window as a set of flows. PACKET_FEATURES describe
packet, TTL, window, retransmission, and inter-arrival behaviour. Time of day
is not a feature. Names that start with log1p_ are log1p-transformed before
the train-only clip and scaler.
"""

FIN = 1
SYN = 2
RST = 4
PSH = 8
ACK = 16
URG = 32
TCP_FLAG_BITS = (
    ("fin_ratio", FIN),
    ("syn_ratio", SYN),
    ("rst_ratio", RST),
    ("psh_ratio", PSH),
    ("ack_ratio", ACK),
    ("urg_ratio", URG),
)

FLOW_FEATURES = [
    "log1p_n_flows",
    "log1p_in_bytes",
    "log1p_out_bytes",
    "log1p_in_pkts",
    "log1p_out_pkts",
    "log1p_out_in_byte_ratio",
    "mean_log1p_duration",
    "fin_ratio",
    "syn_ratio",
    "rst_ratio",
    "psh_ratio",
    "ack_ratio",
    "urg_ratio",
    "tcp_share",
    "udp_share",
    "icmp_share",
    "log1p_uniq_src_ips",
    "log1p_uniq_dst_ips",
    "log1p_uniq_dst_ports",
]

PACKET_FEATURES = [
    "log1p_port_scan_score",
    "mean_min_ttl",
    "mean_max_ttl",
    "log1p_ttl_var",
    "log1p_mean_tcp_win_max_in",
    "log1p_mean_tcp_win_max_out",
    "retrans_ratio",
    "log1p_iat_mean",
    "log1p_iat_max",
    "log1p_iat_std",
]

FEATURES = FLOW_FEATURES + PACKET_FEATURES

HEAVY_FEATURES = [name for name in FEATURES if name.startswith("log1p_") or name == "mean_log1p_duration"]

SEQ_LEN = 10
ROLLOUT_K = 5
EVAL_HORIZONS = (0, 1, 3, 5)
AUX_WEIGHT = 0.3
PURGE_WINDOWS = SEQ_LEN + ROLLOUT_K
GAP_MS = 10 * 60 * 1000
V3_STAGES = ["benign", "initial_access", "lateral_movement", "command_and_control"]
