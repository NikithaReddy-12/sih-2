# Model artifacts

This directory contains the offline artifacts used by the host forecast demo and the benchmark outputs used to describe them.

## Host artifacts

- `v3_host_lstm_seed0.pt` through `v3_host_lstm_seed3.pt`: four saved host LSTM models. The demo loads `v3_host_lstm_seed0.pt` at runtime.
- `v3_host_logistic_window_seed0.joblib` through `v3_host_logistic_window_seed3.joblib`: four host single-window logistic benchmark models.
- `v3_host_logistic_flat10_seed0.joblib` through `v3_host_logistic_flat10_seed3.joblib`: four host flattened-10-window logistic benchmark models.

The host logistic files are benchmark artifacts only. The runtime host forecast route uses the seed-0 LSTM and does not select a logistic model.

## Benchmark and diagnostics

- `benchmark_v3_host.json`: host-level benchmark results, split details, seeds, notes, and diagnostic summaries. Benchmark-only.
- `benchmark_v3.json`: earlier network-level benchmark results. Benchmark-only.
- `diag_hosts.json`: host identity and false-positive diagnostic output. Benchmark/diagnostic-only; the demo does not load it to score forecasts.

## Archive

`archive/` contains older CIC-IDS-2018 and world-model benchmark JSON files. They are retained for historical comparison and are not loaded by the current host forecast route.

The runtime also retains separate legacy network and synthetic artifacts such as `baseline.joblib`, `baseline_cicids2018.joblib`, `world_model_cicids2018.pt`, and their scaler. Their consumers are the legacy CIC/synthetic forecast routes and tests, not the host LSTM path.
