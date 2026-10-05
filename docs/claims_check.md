# Claims check

This ledger checks the current repo state against the saved code and benchmark files.

| Claim | Source |
|---|---|
| `POST /api/forecast/netflow-v3-host` accepts NetFlow-V3 CSV and PCAP uploads | backend/api/routes/forecast.py |
| Scapy PCAP input is mapped into NetFlow-style columns and passed through the host pipeline | backend/ml/pcap_ingest.py; backend/api/routes/forecast.py |
| Host windows are aggregated at 60s, with `min_flows=3` and top-host filtering | backend/ml/host_v3.py; backend/ml/host_forecast.py |
| The LSTM learns `initial_access`, `lateral_movement`, and `command_and_control` | backend/ml/models/benchmark_v3_host.json; backend/ml/host_forecast.py |
| Reconnaissance (`TA0043`) and exfiltration (`TA0010`) are separate heuristic signals, not learned stages | backend/ml/heuristic_stages.py; README.md |
| Recon/exfil rules are only synthetic-capture validation, not benchmarked real data | README.md; backend/ml/heuristic_stages.py; scripts/generate_sample_pcap.py |
| Heuristic rules fired on hosts without dataset labels in labelled samples; status unresolved | README.md |
| Host benchmark is macro-F1 with attack-vs-benign precision/recall/FPR | backend/ml/models/benchmark_v3_host.json |
| Earlier network-view benchmark is separate from the host view | backend/ml/models/benchmark_v3.json |
| Persistence is higher macro-F1 at host h3, but LSTM is lower FPR | backend/ml/models/benchmark_v3_host.json |
| LSTM initial-access F1 is 0.0 in the one-attacker brute-force case | backend/ml/models/benchmark_v3_host.json |
| Host-level onset values are from `benchmark_v3_host.json` and network onset values are from `benchmark_v3.json` | backend/ml/models/benchmark_v3_host.json; backend/ml/models/benchmark_v3.json |
| Network risk is `max over hosts of 1 - P(benign)` and not calibrated | backend/ml/host_forecast.py |
| Identity diagnostic FPRs and near-attack bands come from `diag_hosts.json` | backend/ml/models/diag_hosts.json |
| Brute-force active windows reach 0.962-0.985 as the highest host probability in the window | runtime script: `scripts/_verify_bruteforce.py` |
| In the brute-force sample, the highest-probability host is `13.58.98.64`, stage `command_and_control` | runtime script: `scripts/_verify_bruteforce.py` |
| After the attacker stops, the future probabilities are `0.063`, `0.019`, and `0.017` and no host is flagged | runtime script: `scripts/_verify_bruteforce.py` |
| Budgeted ablation and leave-one-attack-out procedures are not full-data comparisons | backend/ml/models/benchmark_v3_host.json notes |
| PCAP path was only tested on synthetic bundled files, not a labelled PCAP dataset | backend/ml/pcap_ingest.py; README.md |
| Real labelled PCAP benchmark or production validation result | [MISSING] |
| External dataset provenance or operational impact metrics | [MISSING] |

The repo does not claim a generalised unseen-host result, a labelled real-PCAP benchmark, or an operational deployment metric beyond the packaged synthetic validation and benchmark files.
