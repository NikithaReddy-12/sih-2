# PREDICT-X: architecture

## Setup and run

- Backend: `pip install -r backend/requirements.txt` and `pip install -r backend/requirements-dev.txt`.
- FastAPI `TestClient` uses the `httpx` package underneath, so `backend/requirements-dev.txt` includes `pytest` and `httpx` for local validation.
- Start the backend on port 8000 from the repo root: `cd backend` then `python main.py` (equivalently `uvicorn main:app --host 0.0.0.0 --port 8000`).
- Frontend setup: `npm install`, then `npm run dev`.
- Demo entry points: `npm run demo` on Windows, and `scripts/run_demo.sh` on Linux/macOS.
  - Syntax-checked only; not run in this environment.

**Problem.** Intrusion classifiers label each flow alone, so they alert only once an attack is visible and lose the order of events. PREDICT-X models how each host's behaviour evolves, scores what it may do over the next five minutes, and tells an analyst which hosts to look at first and why.

**Data.** NF-CICIDS2018-v3, the NetFlow-v3 form of CSE-CIC-IDS2018 from the University of Queensland NIDS datasets page (https://staff.itee.uq.edu.au/marius/NIDS_datasets/): 20,115,529 flows with flow-level and packet-derived columns (TTL, TCP window, retransmissions, inter-arrival times). Stage labels are proxies from the dataset's attack categories: brute force is initial access, infiltration is lateral movement, bot traffic is command and control. DoS, DDoS and web attacks are excluded because they are not kill-chain stages.

**State representation.** One row per (60-second window, source host): 921,096 rows, at least 3 flows, at most 500 hosts per window. 29 features: 15 flow-level (TCP flag ratios, bytes, duration, unique destinations and ports, no-response and small-flow shares), 9 packet-level (port-scan score, TTL mean and variance, TCP window, retransmission ratio, inter-arrival statistics), 2 concentration (top destination port and IP share) and 3 context (window volume, active hosts, host-active flag).

**World model.** A one-layer LSTM (hidden size 64) reads the last 10 windows of a host. It outputs the current stage distribution and a K=5 rollout of future stage distributions, with an auxiliary loss that predicts the next window's feature vector (weight 0.3). Training used 563,653 host-windows from a chronological split with purge gaps, four seeds; the demo API serves seed 0.

**Outputs.** (1) A network timeline: the highest host attack probability in each window, max over hosts of 1 - P(benign), which is not calibrated. (2) Current detection: hosts above 0.5 in the last three observed windows. (3) Forecast hosts: above 0.5 on the future steps. Each host has a predicted stage with MITRE tactic (TA0001, TA0008, TA0011), its top-5 features and up to five flows from its peak window.

**Explainability.** Gradient times input on the log-odds of the predicted stage, summed over the 10-window input and reported as each feature's share of total absolute attribution, grouped as flow, packet, concentration or context. Log-odds are used because the softmax saturates at 1.0 and its gradient vanishes. The result shows what the model is sensitive to, not causes. Forecast and observed-window explanations are labelled separately.

## Results (host level, test split)

Macro-F1 over benign and the three stages, mean of four seeds:

| Model | h0 | h1 | h3 | h5 |
|---|---:|---:|---:|---:|
| LSTM | 0.603 | 0.575 | 0.576 | 0.577 |
| Logistic (1 window) | 0.732 | 0.490 | 0.486 | 0.482 |
| Logistic (10 windows) | 0.535 | 0.521 | 0.514 | 0.510 |
| Persistence | 0.732 | 0.721 | 0.713 | 0.705 |

Attack versus benign at horizon 3:

| Model | Precision | Recall | FPR |
|---|---:|---:|---:|
| LSTM | 0.490 | 0.935 | 0.0062 |
| Logistic (1 window) | 0.054 | 0.977 | 0.1027 |
| Logistic (10 windows) | 0.176 | 0.954 | 0.0270 |
| Persistence | 0.057 | 0.980 | 0.0982 |

Against the logistic baselines the LSTM has a much lower false-positive rate and far higher precision at every horizon, with 1 to 7 points less recall. Its macro-F1 is higher than the 10-window logistic at every horizon (difference +0.069, +0.053, +0.063, +0.069) and higher than the single-window logistic at horizons 1, 3 and 5 (+0.084, +0.092, +0.098); the 95% block-bootstrap intervals exclude zero in all four seeds. At horizon 0 the single-window logistic is higher (-0.130). Persistence, which repeats the current-stage guess, has the highest macro-F1 at every horizon, so this is a trade-off and not an overall win. By stage at horizon 0 the LSTM scores 0.485 F1 on lateral movement (logistic 0.080 and 0.225), 0.933 on command and control (logistic 0.961 and 0.927) and 0.0 on initial access, a single attacker host with 98 training rows.

Early warning (does an attack start within five windows) is weak for every model: onset precision is 0.037 for the LSTM and 0.002, 0.005 and 0.002 for the single-window logistic, 10-window logistic and persistence, at recall 0.36, 0.47, 0.36 and 0.46.

## Rules and PCAP

Reconnaissance (TA0043) and exfiltration (TA0010) have rule-based signals that are separate from the LSTM and are in no benchmark. They were validated only on synthetic captures from `scripts/generate_sample_pcap.py`, and in the labelled samples they fired on hosts that carry no dataset label (reconnaissance flags: bot 1, brute force 2, replay 3; no exfiltration flags), which is unresolved. PCAP files are parsed with Scapy into NetFlow-style columns and scored by the same pipeline; those features approximate the training features and were tested only on bundled synthetic captures.

## Known limitations

- Heuristic recon/exfil rules are not validated on real labelled data and are demonstration-level signals rather than benchmark-tuned detectors.
- Reconnaissance is tuned to roughly 20 distinct destination ports per minute across 2 windows (`log1p_uniq_dst_ports >= log1p(20)` and `required_windows = 2`), so slow or stealthy scans can evade it.
- Unlabelled heuristic flags remain unresolved; the same synthetic sample may produce alerts on hosts that carry no dataset label and cannot be cleanly interpreted as a real attack.
- PCAP features are approximate proxies for the NetFlow-v3 training schema, not a separate labelled benchmark; they were tested on bundled synthetic captures rather than a ground-truth operational dataset.
- Long flows are split at 60 seconds and hosts with fewer than 3 flows in a window are dropped before scoring; this is a deliberate pipeline choice in the host aggregation logic.
- Explainability is gradient x input attribution on predicted-stage log-odds, not SHAP, attention, or a causal explanation of root cause.
- The Simulated views are mockups built from hard-coded data and not a live sensor feed.

## Legacy components

The project still contains legacy or exploratory files that are not part of the shipped production path:

- `backend/ml/cicids.py`
- `backend/ml/world_model_impl.py`
- `backend/ml/synth.py`
- `backend/ml/train.py`
- `/api/forecast`
- `/api/forecast/cicids`
- `/api/forecast/demo`

The shipped model path is the host LSTM on `/api/forecast/netflow-v3-host`.

## Limits

Labels are proxies and the evaluation uses one dataset. The same internal machines act as attackers on several days and appear in both training and test periods. On benign test rows the LSTM's false-positive rate is 0.54% for hosts that never carry an attack label and 5.81% for hosts that do (11.1 times after volume matching); the excess is concentrated in hosts that attack during the test period, but whether that reflects label boundaries or learned host behaviour is unresolved, and a host-disjoint test was not run. Leave-one-attack-out and ablation runs used a budgeted two-seed procedure and are not comparable with the full-data results.

## Applicability

PREDICT-X runs offline with open-source components and no cloud calls, so it fits enterprise networks and Critical Information Infrastructure where traffic cannot leave the site: a SPAN port or TAP feeds a capture, and an analyst uploads it for triage. It is decision support, not an autonomous verdict.

Analyst workflow: SPAN/TAP capture -> PCAP upload -> current vs forecast hosts -> heuristic recon/exfil cards -> triage.
