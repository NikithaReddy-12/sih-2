"""Host forecast mode: shared aggregation, gradient x input, and the upload contract."""
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from fastapi.testclient import TestClient

from main import app
from ml.host_forecast import (
    HOST_LSTM_NAME,
    NETWORK_RISK_DEFINITION,
    attribute_sequence,
    feature_group,
    forecast_host_file,
    top_attributions,
    stage_probability,
)
from ml.host_v3 import PASS2_COLS, aggregate_host_windows
from ml.host_forecast import _scale
from ml.host_train import stack_host
from ml.model_v3 import load_lstm
from ml.baseline import MODELS_DIR
from ml.netflow_v3 import _ipv4_to_uint32


def _flow_row(ts, src, dst, port, attack="Benign", flags=2, protocol=6, in_bytes=100, out_bytes=40):
    row = {name: 0 for name in PASS2_COLS}
    row.update({
        "FLOW_START_MILLISECONDS": ts,
        "IPV4_SRC_ADDR": src,
        "IPV4_DST_ADDR": dst,
        "L4_DST_PORT": port,
        "PROTOCOL": protocol,
        "IN_BYTES": in_bytes,
        "OUT_BYTES": out_bytes,
        "IN_PKTS": 2,
        "OUT_PKTS": 1,
        "TCP_FLAGS": flags,
        "FLOW_DURATION_MILLISECONDS": 20,
        "MIN_TTL": 64,
        "MAX_TTL": 64,
        "Attack": attack,
    })
    return row


def _write_capture(path: Path, rows: list[dict]) -> None:
    pd.DataFrame(rows).to_csv(path, index=False)


class HostForecastTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_missing_columns_are_named_in_422(self):
        raw = b"FLOW_START_MILLISECONDS,IPV4_SRC_ADDR\n1,10.0.0.1\n"
        response = self.client.post(
            "/api/forecast/netflow-v3-host",
            files={"file": ("flows.csv", raw, "text/csv")},
        )
        self.assertEqual(response.status_code, 422)
        detail = response.json()["detail"]
        self.assertIn("Missing required columns:", detail)
        self.assertIn("Attack", detail)
        self.assertIn("L4_DST_PORT", detail)

    def test_upload_over_200mb_is_rejected(self):
        from api.routes import forecast as route
        previous = route.HOST_UPLOAD_LIMIT
        route.HOST_UPLOAD_LIMIT = 8
        try:
            response = self.client.post(
                "/api/forecast/netflow-v3-host",
                files={"file": ("flows.csv", b"0123456789", "text/csv")},
            )
        finally:
            route.HOST_UPLOAD_LIMIT = previous
        self.assertEqual(response.status_code, 413)

    def test_aggregate_uses_min_flows_and_not_labels(self):
        rows = []
        base = 1_518_611_287_705
        for index in range(3):
            rows.append(_flow_row(base + index, "10.0.0.1", "10.0.0.8", 22))
            rows.append(_flow_row(base + index, "10.0.0.2", "10.0.0.9", 80, attack="Benign"))
        rows.append(_flow_row(base, "10.0.0.3", "10.0.0.9", 443, attack="FTP-BruteForce"))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.csv"
            _write_capture(path, rows)
            table, _meta, flows = aggregate_host_windows(path, window_s=60, keep_flows=True)
        sources = set(int(value) for value in table["src"].to_numpy())
        dropped = int(_ipv4_to_uint32(pd.Series(["10.0.0.3"]))[0])
        self.assertEqual(len(table), 2)
        self.assertEqual(len(flows), 6)
        self.assertNotIn(dropped, sources)

    def test_logodds_attribution_top_feature_beats_random_feature(self):
        bundle = load_lstm(MODELS_DIR / HOST_LSTM_NAME)
        model = bundle["model"]
        features = list(bundle["features"])
        width = len(features)
        stages = list(bundle["stages"])
        sample = Path(__file__).resolve().parents[1] / "samples" / "bot.csv.gz"
        table, _meta, _flows = aggregate_host_windows(sample, window_s=60, keep_flows=False)
        kept = table.loc[table["stage"] != "dropped"].reset_index(drop=True)
        scaled = _scale(kept, features, bundle["clip_high"], bundle["scaler"])
        hosts = kept["src"].to_numpy(np.uint32)
        windows = kept["window"].to_numpy(np.int64)
        positions = {(int(hosts[index]), int(windows[index])): index for index in range(len(kept))}
        anchors = np.arange(len(kept), dtype=np.int64)
        seqs, _next, _labels = stack_host(
            scaled, hosts, windows, np.zeros(len(kept), np.int64), anchors, positions, 10, 5,
        )
        rng = np.random.default_rng(0)
        drops_top = []
        drops_random = []
        for seq in seqs[rng.choice(len(seqs), size=50, replace=False)]:
            step = 1
            scores = [stage_probability(model, seq, index, step, 5) for index in range(len(stages))]
            stage_index = int(np.argmax(scores))
            product = attribute_sequence(model, seq, stage_index, step, 5)
            self.assertEqual(product.shape, (10, width))
            self.assertTrue(np.isfinite(product).all())
            self.assertGreater(float(np.abs(product).sum()), 0.0)
            ranking = product.sum(axis=0)
            top = int(np.argmax(ranking))
            others = [index for index in range(width) if index != top]
            random_feature = int(others[int(rng.integers(0, len(others)))])
            def logodds(values):
                with torch.no_grad():
                    logits = model(torch.tensor(values[None], dtype=torch.float32), 5)[1][:, step - 1]
                    other = torch.cat((logits[:, :stage_index], logits[:, stage_index + 1:]), dim=-1)
                    return float((logits[:, stage_index] - torch.logsumexp(other, dim=-1))[0])
            base = logodds(seq)
            zero_top = seq.copy()
            zero_top[:, top] = 0
            zero_random = seq.copy()
            zero_random[:, random_feature] = 0
            drops_top.append(base - logodds(zero_top))
            drops_random.append(base - logodds(zero_random))
            self.assertIn(feature_group(features[top]), {"FLOW", "PACKET", "CONCENTRATION", "CONTEXT"})
        self.assertGreater(float(np.mean(drops_top)), float(np.mean(drops_random)))

    def test_bot_first_flagged_host_has_distinct_top_attributions(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "bot.csv.gz"
        body = forecast_host_file(sample, k=5)
        self.assertEqual(body["method"], "gradient_x_input_logodds")
        self.assertEqual(len(body["explanation"]), 5)
        self.assertTrue(body["explanation_host"])
        self.assertEqual(body["explanation_source"], "forecast_step_1")
        self.assertTrue(all(float(row["share"]) > 0 for row in body["explanation"]))
        self.assertTrue(all(abs(float(row["attribution"])) > 1e-6 for row in body["explanation"]))
        self.assertEqual(
            [row["attribution"] for row in body["explanation"]],
            sorted((row["attribution"] for row in body["explanation"]), reverse=True),
        )
        self.assertTrue(all(host["explanation"] for host in body["current_hosts"] + body["hosts"]))
        self.assertTrue(all(host["explanation_source"] == "forecast_step_1" for host in body["hosts"]))
        self.assertTrue(all(host["explanation_source"] == "observed_window" for host in body["current_hosts"]))
        self.assertTrue(body["current_hosts"])
        top = body["current_hosts"][0]["explanation"]
        self.assertEqual(len(top), 5)
        values = [abs(float(row["attribution"])) for row in top]
        self.assertTrue(all(value > 1e-6 for value in values))
        self.assertEqual(values, sorted(values, reverse=True))
        self.assertGreater(len(set(values)), 1)

    def test_samples_use_stage_counts_without_stage_match(self):
        response = self.client.get("/api/samples")
        self.assertEqual(response.status_code, 200)
        bot = response.json()["ground_truth"]["samples"]["bot.csv.gz"]
        for verdict in (bot["current"], bot["forecast"]):
            self.assertIn("stage_matched", verdict)
            self.assertIn("stage_total", verdict)
            self.assertIn("flagged_unlabelled", verdict)
            self.assertNotIn("stage_match", verdict)

    def test_bot_api_response_uses_logodds_explanation(self):
        sample = Path(__file__).resolve().parents[1] / "samples" / "bot.csv.gz"
        response = self.client.post(
            "/api/forecast/netflow-v3-host",
            files={"file": (sample.name, sample.read_bytes(), "application/gzip")},
        )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["method"], "gradient_x_input_logodds")
        self.assertTrue(body["explanation_host"])
        self.assertEqual(body["explanation_source"], "forecast_step_1")
        self.assertEqual(len(body["explanation"]), 5)
        self.assertTrue(all(float(row["share"]) > 0 for row in body["explanation"]))
        self.assertTrue(all(abs(float(row["attribution"])) > 1e-6 for row in body["explanation"]))
        self.assertTrue(all(host["explanation"] for host in body["current_hosts"] + body["hosts"]))

    def test_host_response_adds_fields_and_names_seed(self):
        rows = []
        base = 1_518_611_287_705
        for window in range(12):
            ts = base + window * 60_000
            for copy in range(3):
                rows.append(_flow_row(
                    ts + copy,
                    "10.1.0.4",
                    "10.2.0.5",
                    22 if window > 8 else 443,
                    flags=2,
                ))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hosts.csv"
            _write_capture(path, rows)
            body = forecast_host_file(path, k=3)
        self.assertEqual(body["model"], "netflow_v3_host")
        self.assertEqual(body["method"], "gradient_x_input_logodds")
        self.assertIn("seed 0", " ".join(body["notes"]))
        self.assertEqual(
            [row["mitre_id"] for row in body["mitre"]],
            ["TA0001", "TA0008", "TA0011"],
        )
        self.assertEqual(body["not_predicted_stages"], [])
        self.assertEqual(body["heuristic_stage_names"], ["reconnaissance", "exfiltration"])
        self.assertIn("initial_access", body["supported_stages"])
        self.assertNotIn("reconnaissance", body["supported_stages"])
        self.assertTrue(body["timeline"])
        self.assertTrue(any(not row["observed"] for row in body["timeline"]))
        self.assertEqual(body["flag_basis"], "future")
        self.assertEqual(body["network_risk_definition"], NETWORK_RISK_DEFINITION)
        observed_times = [row["t"] for row in body["timeline"] if row["observed"]]
        last_observed = set(observed_times[-3:])
        self.assertIsInstance(body["current_hosts"], list)
        self.assertLessEqual(len(body["current_hosts"]), 20)
        for host in body["current_hosts"]:
            self.assertGreater(host["peak_attack_prob"], 0.5)
            times = [step["t"] for step in host["per_step_attack_prob"]]
            self.assertTrue(times)
            self.assertLessEqual(len(times), 3)
            self.assertTrue(all(item in last_observed for item in times))
            self.assertEqual(host["peak_attack_prob"], max(step["attack_prob"] for step in host["per_step_attack_prob"]))
            self.assertLessEqual(len(host["flows_in_flagged_window"]), 5)
            self.assertTrue(host["explanation"])
            self.assertTrue(all(np.isfinite(row["attribution"]) for row in host["explanation"]))
            self.assertTrue(all(step["t"] in observed_times for step in host["per_step_attack_prob"]))
        future_rows = [row for row in body["timeline"] if not row["observed"]]
        self.assertEqual(body["overall_risk"], max(row["attack_prob"] for row in future_rows))
        future_times = {row["t"] for row in future_rows}
        self.assertIsInstance(body["hosts"], list)
        peaks = []
        for host in body["hosts"]:
            self.assertGreater(host["peak_attack_prob"], 0.5)
            future_probs = [
                step["attack_prob"] for step in host["per_step_attack_prob"] if step["t"] in future_times
            ]
            self.assertTrue(future_probs)
            self.assertEqual(host["peak_attack_prob"], max(future_probs))
            self.assertLessEqual(len(host["flows_in_flagged_window"]), 5)
            self.assertTrue(host["explanation"])
            self.assertTrue(all(np.isfinite(row["attribution"]) for row in host["explanation"]))
            self.assertIn(host["mitre_tactic"], {"Initial Access", "Lateral Movement", "Command and Control", "Benign"})
            peaks.append(host["peak_attack_prob"])
        self.assertGreaterEqual(body["overall_risk"], max(peaks, default=0))
