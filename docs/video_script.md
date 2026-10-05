# Two-minute video script

## 0:00-0:18 - What the system actually predicts

Open the Attack Forecast page. Explain that the project learns `initial_access`, `lateral_movement`, and `command_and_control`; a separate heuristic branch handles `reconnaissance` and `exfiltration`, and those rules are not part of the learned model. Point to the `current` and `forecast` host panels and say the learned model does not predict the heuristic stages.

Screen step: show the model state and sample selector, then point to the host route and the fact that PCAP is accepted via the same host pipeline.

## 0:18-0:42 - PCAP demo and heuristic cards

Upload `recon_exfil_demo.pcap`. Explain that the PCAP path converts packets into NetFlow-style rows and scores them with the host window pipeline; it is a practical approximation of the training feature schema. The learned panel shows no hosts because the LSTM has no explicit training for `reconnaissance` or `exfiltration`.

Screen step: show the two heuristic cards that appear: `10.1.0.50` as `reconnaissance` and `10.1.0.60` as `exfiltration`. Keep the narration to about 25 seconds and say those are heuristic signals, not learned stage predictions.

## 0:42-1:08 - Host forecast and network risk

Show the host forecast view. The LSTM sees a 10-window host sequence and forecasts the next 5 windows. The network timeline is the highest host attack probability in the window, not a calibrated probability; current detection looks at the last three observed windows. The explanations are gradient x input attributions, not SHAP or attention.

Screen step: scrub the timeline while pointing to the highest host value and the current-vs-forecast separation.

## 1:08-1:30 - Brute-force verification

Load `brute_force.csv.gz`. Explain that the active windows hit `0.962` to `0.985` as the highest host probability in the window; the host is `13.58.98.64` and the stage is `command_and_control`. After the attacker stops, the future probabilities drop to `0.063`, `0.019`, and `0.017`, and the network returns to a benign state.

Screen step: scrub the timeline from the active attack interval to the later benign windows and show that no host remains flagged.

## 1:30-1:50 - Benchmark and caveats

Show the host benchmark and state that persistence has higher macro-F1 at h3 (`0.713145` vs `0.576085`), while the LSTM has lower FPR (`0.006246` vs `0.098204`). The host-level onset values are small precision and moderate recall, the network view is the earlier representation, and the identity diagnostic shows non-trivial FPR on ever-attack hosts.

## 1:50-2:00 - Decision-support impact

Close on the operational point: this is a way to prioritise hosts, separate current evidence from future evidence, and surface heuristic recon/exfil context without claiming autonomous verdicts. The repo does not contain a labelled PCAP benchmark or production validation evidence; the current documented claims are scoped to the synthetic sample and benchmark files.
