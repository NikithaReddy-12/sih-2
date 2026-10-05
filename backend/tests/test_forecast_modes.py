"""Forecast modes: synthetic logistic demo stays separate from the CIC LSTM path."""
import io
import os
import tempfile
import unittest
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from main import app
from ml import forecast as fc
from ml.cicids import (
    CAPTURE_FILES,
    capture_paths,
    load_capture,
    map_stage,
    resolve_data_dir,
    windows_to_frame,
)
from ml.features import CIC_FEATURES, FEATURES
from ml.forecast import CIC_SUPPORTED_STAGES, CICIDS, SYNTHETIC
from ml.stages import STAGES
from ml.synth import make_windows
from ml.world_model_impl import load_world_model
from ml.baseline import MODELS_DIR


def _cic_csv() -> bytes:
    rows = ["Timestamp,Dst Port,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,SYN Flag Cnt,RST Flag Cnt,Flow IAT Mean,Label"]
    stamps = ["14/02/2018 10:00:00", "14/02/2018 10:01:00", "14/02/2018 10:02:00", "14/02/2018 10:03:00"]
    labels = ["Benign", "Benign", "FTP-BruteForce", "Infilteration"]
    for stamp, label in zip(stamps, labels):
        for index in range(8):
            rows.append(f"{stamp},80,{1000 + index},10,4,400,80,1,0,20,{label}")
    rows.append("Timestamp,Dst Port,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,TotLen Fwd Pkts,TotLen Bwd Pkts,SYN Flag Cnt,RST Flag Cnt,Flow IAT Mean,Label")
    return ("\n".join(rows) + "\n").encode()


class ForecastModeTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        fc._cache.clear()

    def tearDown(self):
        fc._cache.clear()

    def test_status_reports_separate_models(self):
        body = self.client.get("/api/forecast/status").json()
        self.assertTrue(body["synthetic_baseline_loaded"])
        self.assertTrue(body["cic_baseline_loaded"])
        self.assertTrue(body["cic_world_model_loaded"])
        self.assertEqual(body["active_mode"], CICIDS)
        self.assertEqual(body["demo_mode"], SYNTHETIC)
        self.assertEqual(body["modes"][SYNTHETIC]["future_model"], "logistic_regression")
        self.assertEqual(body["modes"][CICIDS]["future_model"], "world_model_cicids2018.pt")
        self.assertEqual(
            body["modes"][CICIDS]["supported_stages"],
            ["benign", "initial_access", "lateral_movement", "command_and_control"],
        )
        self.assertEqual(
            body["modes"][CICIDS]["not_predicted_from_this_subset"],
            ["reconnaissance", "exfiltration"],
        )

    def test_data_dir_bot_mapping_and_missing_capture(self):
        self.assertEqual(map_stage("Bot"), "command_and_control")
        self.assertEqual(map_stage("Brute Force -Web"), "initial_access")
        self.assertEqual(map_stage("Brute Force -XSS"), "initial_access")
        self.assertEqual(map_stage("SQL Injection"), "initial_access")
        self.assertEqual(map_stage("Infilteration"), "lateral_movement")
        for name in (
            "Friday-02-03-2018_TrafficForML_CICFlowMeter.csv",
            "Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv",
            "Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv",
            "Friday-23-02-2018_TrafficForML_CICFlowMeter.csv",
        ):
            self.assertIn(name, CAPTURE_FILES)
        previous = os.environ.get("PREDICT_X_DATA_DIR")
        try:
            os.environ.pop("PREDICT_X_DATA_DIR", None)
            with self.assertRaises(FileNotFoundError):
                resolve_data_dir()
            os.environ["PREDICT_X_DATA_DIR"] = r"C:\from-env"
            self.assertEqual(resolve_data_dir(), Path(r"C:\from-env"))
            self.assertEqual(resolve_data_dir(Path(r"C:\from-cli")), Path(r"C:\from-cli"))
        finally:
            if previous is None:
                os.environ.pop("PREDICT_X_DATA_DIR", None)
            else:
                os.environ["PREDICT_X_DATA_DIR"] = previous
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            present = root / CAPTURE_FILES[0]
            present.write_text("Timestamp\n", encoding="utf-8")
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                found = capture_paths(root)
            self.assertEqual(found, [present])
            self.assertTrue(any("Friday-02-03-2018" in str(item.message) for item in caught))

    def test_feature_list_appends_cic_columns_and_drops_ip_features_for_cic(self):
        added = [
            "mean_init_fwd_win_byts", "mean_init_bwd_win_byts",
            "psh_ratio", "ack_ratio", "fin_ratio", "urg_ratio",
            "log_mean_flow_iat_max", "log_mean_pkt_len_var",
        ]
        self.assertEqual(FEATURES[-len(added):], added)
        self.assertIn("uniq_src_ips", FEATURES)
        self.assertIn("uniq_dst_ips", FEATURES)
        self.assertNotIn("uniq_src_ips", CIC_FEATURES)
        self.assertNotIn("uniq_dst_ips", CIC_FEATURES)
        for name in added:
            self.assertIn(name, CIC_FEATURES)
        synthetic = make_windows(n_episodes=1, seed=0)
        self.assertEqual([column for column in synthetic.columns if column in FEATURES], FEATURES)
        frame = windows_to_frame({
            pd.Timestamp("2018-02-14 10:00:00"): {
                "n": 4,
                "duration": 40.0, "fwd_pkts": 8.0, "bwd_pkts": 4.0,
                "fwd_bytes": 100.0, "bwd_bytes": 20.0,
                "syn": 1, "rst": 0, "iat": 80.0,
                "init_fwd": 400.0, "init_bwd": 200.0, "init_fwd_n": 4, "init_bwd_n": 4,
                "psh": 2, "ack": 4, "fin": 1, "urg": 0,
                "iat_max": 400.0, "pkt_var": 80.0,
                "ports": {80}, "src_ips": set(), "dst_ips": set(),
                "labels": {"Benign": 4},
            },
        }, False, False)
        self.assertEqual(frame.loc[0, "mean_init_fwd_win_byts"], 100.0)
        self.assertEqual(frame.loc[0, "mean_init_bwd_win_byts"], 50.0)
        self.assertEqual(frame.loc[0, "psh_ratio"], 0.5)
        self.assertEqual(frame.loc[0, "ack_ratio"], 1.0)
        self.assertEqual(frame.loc[0, "fin_ratio"], 0.25)
        self.assertEqual(frame.loc[0, "urg_ratio"], 0.0)
        self.assertAlmostEqual(frame.loc[0, "log_mean_pkt_len_var"], float(np.log1p(20.0)))
        self.assertEqual(frame.loc[0, "uniq_src_ips"], 0)
        self.assertEqual(frame.loc[0, "uniq_dst_ips"], 0)
        self.assertGreater(frame.loc[0, "log_mean_flow_iat_max"], 0)

    def test_init_win_means_exclude_missing_tcp_window(self):
        header = (
            "Timestamp,Dst Port,Flow Duration,Tot Fwd Pkts,Tot Bwd Pkts,"
            "TotLen Fwd Pkts,TotLen Bwd Pkts,SYN Flag Cnt,RST Flag Cnt,Flow IAT Mean,"
            "Init Fwd Win Byts,Init Bwd Win Byts,Label"
        )
        rows = [
            "14/02/2018 10:00:00,80,1000,1,1,10,10,0,0,1,100,-1,Benign",
            "14/02/2018 10:00:10,80,1000,1,1,10,10,0,0,1,-1,80,Benign",
            "14/02/2018 10:00:20,80,1000,1,1,10,10,0,0,1,300,40,Benign",
            "14/02/2018 10:01:00,80,1000,1,1,10,10,0,0,1,-1,-1,Benign",
            "14/02/2018 10:01:05,80,1000,1,1,10,10,0,0,1,-1,-1,Benign",
        ]
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as handle:
            handle.write((header + "\n" + "\n".join(rows) + "\n").encode())
            path = Path(handle.name)
        try:
            windows, _stats = load_capture(path)
            frame = windows_to_frame(windows, False, False).sort_values("window_start")
        finally:
            path.unlink(missing_ok=True)
        self.assertEqual(len(frame), 2)
        mixed = frame.iloc[0]
        self.assertEqual(mixed["n_flows"], 3)
        self.assertEqual(mixed["mean_init_fwd_win_byts"], 200.0)
        self.assertEqual(mixed["mean_init_bwd_win_byts"], 60.0)
        empty = frame.iloc[1]
        self.assertEqual(empty["n_flows"], 2)
        self.assertEqual(empty["mean_init_fwd_win_byts"], 0.0)
        self.assertEqual(empty["mean_init_bwd_win_byts"], 0.0)

    def test_cic_models_load_and_rollout(self):
        bundle = fc._cic_baseline()
        self.assertIn(0, bundle["models"])
        self.assertEqual(list(bundle["features"]), CIC_FEATURES)
        self.assertEqual(int(bundle["scaler"].n_features_in_), len(CIC_FEATURES))
        world = load_world_model(MODELS_DIR)
        self.assertEqual(
            FEATURES[12:],
            [
                "mean_init_fwd_win_byts", "mean_init_bwd_win_byts",
                "psh_ratio", "ack_ratio", "fin_ratio", "urg_ratio",
                "log_mean_flow_iat_max", "log_mean_pkt_len_var",
            ],
        )
        self.assertNotIn("uniq_src_ips", CIC_FEATURES)
        self.assertNotIn("uniq_dst_ips", CIC_FEATURES)
        self.assertEqual(list(world.features), CIC_FEATURES)
        self.assertEqual(world.n_features, len(world.features))
        self.assertIn("log_mean_pkt_len_var", CIC_FEATURES)
        self.assertNotIn("mean_pkt_len_var", CIC_FEATURES)
        probs = world.rollout(np.zeros((world.seq_len, world.n_features)), K=3)
        self.assertEqual(probs.shape, (3, len(STAGES)))
        self.assertTrue(np.allclose(probs.sum(axis=1), 1.0, atol=1e-5))

    def test_world_model_input_size_comes_from_saved_feature_list(self):
        import joblib
        import torch
        from sklearn.preprocessing import StandardScaler

        from ml.world_model_impl import SCALER_NAME, WEIGHTS_NAME, WorldLSTM, load_world_model

        columns = ["a", "b", "c", "d", "e"]
        model = WorldLSTM(n_features=len(columns), n_stages=len(STAGES))
        scaler = StandardScaler().fit(np.zeros((4, len(columns))))
        scaler.feature_columns_ = list(columns)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            torch.save({
                "state_dict": model.state_dict(),
                "config": {
                    "n_features": 12,
                    "features": columns,
                    "n_stages": len(STAGES),
                    "hidden": 64,
                    "embedding": 16,
                    "seq_len": 10,
                },
            }, root / WEIGHTS_NAME)
            joblib.dump(scaler, root / SCALER_NAME)
            loaded = load_world_model(root)
            self.assertEqual(loaded.features, columns)
            self.assertEqual(loaded.n_features, len(columns))
            self.assertEqual(loaded.rollout(np.zeros((3, len(columns))), K=2).shape, (2, len(STAGES)))

            torch.save({
                "state_dict": model.state_dict(),
                "config": {
                    "n_features": 12,
                    "n_stages": len(STAGES),
                    "hidden": 64,
                    "embedding": 16,
                    "seq_len": 10,
                },
            }, root / WEIGHTS_NAME)
            from_scaler = load_world_model(root)
            self.assertEqual(from_scaler.features, columns)
            self.assertEqual(from_scaler.n_features, len(columns))

            legacy = WorldLSTM(n_features=4, n_stages=len(STAGES))
            legacy_scaler = StandardScaler().fit(np.zeros((3, 4)))
            torch.save({
                "state_dict": legacy.state_dict(),
                "config": {
                    "n_features": 4,
                    "n_stages": len(STAGES),
                    "hidden": 64,
                    "embedding": 16,
                    "seq_len": 10,
                },
            }, root / WEIGHTS_NAME)
            joblib.dump(legacy_scaler, root / SCALER_NAME)
            old = load_world_model(root)
            self.assertIsNone(old.features)
            self.assertEqual(old.n_features, 4)
            self.assertEqual(old.rollout(np.zeros((2, 4)), K=1).shape, (1, len(STAGES)))

    def test_forecast_reads_each_artifact_feature_list(self):
        captured = {}

        class Scaler:
            def transform(self, values):
                return np.asarray(values, dtype=float)

        class CurrentStage:
            classes_ = np.array([0])

            def predict_proba(self, values):
                return np.ones((len(values), 1))

        class World:
            features = ["n_flows", "syn_ratio"]
            n_features = 2

            def rollout(self, windows, k):
                captured["windows"] = np.asarray(windows, dtype=float)
                probs = np.zeros((k, len(STAGES)))
                probs[:, 0] = 1.0
                return probs

        fc._cache["cic"] = {
            "scaler": Scaler(),
            "models": {0: CurrentStage()},
            "features": ["n_flows", "log_mean_duration"],
        }
        fc._cache["cic_world"] = World()
        frame = pd.DataFrame({
            "n_flows": [1.0, 2.0, 3.0, 4.0],
            "log_mean_duration": [0.1, 0.2, 0.3, 0.4],
            "syn_ratio": [0.5, 0.6, 0.7, 0.8],
        })
        times = list(pd.date_range("2018-02-14 10:00", periods=len(frame), freq="min"))
        body = fc.forecast(frame, times, K=1, mode=CICIDS)
        self.assertEqual(body["model"], CICIDS)
        self.assertEqual(captured["windows"].shape, (4, 2))
        self.assertTrue(np.allclose(captured["windows"][:, 0], [1.0, 2.0, 3.0, 4.0]))
        self.assertTrue(np.allclose(captured["windows"][:, 1], [0.5, 0.6, 0.7, 0.8]))

    def test_synthetic_demo_does_not_use_lstm(self):
        response = self.client.get("/api/forecast/demo")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["model"], "logistic_regression")
        self.assertTrue(any(entry["observed"] for entry in body["timeline"]))
        self.assertTrue(any(not entry["observed"] for entry in body["timeline"]))
        frame = make_windows(n_episodes=1, seed=11)
        times = list(pd.date_range("2018-02-15 10:00", periods=len(frame), freq="min"))
        cut = int(len(frame) * 0.55)
        features = frame.iloc[:cut][FEATURES].reset_index(drop=True)
        direct = fc.forecast(features, times[:cut], K=3, mode=SYNTHETIC)
        self.assertEqual(direct["model"], "logistic_regression")
        bundle = fc._synthetic_baseline()
        saved = list(bundle["features"])
        scaled = bundle["scaler"].transform(features[saved].to_numpy(dtype=float))
        logistic_stage = STAGES[list(bundle["models"][1].classes_)[int(np.argmax(bundle["models"][1].predict_proba(scaled[-1:])[0]))]]
        future = [entry for entry in direct["timeline"] if not entry["observed"]]
        self.assertEqual(future[0]["stage"], logistic_stage)
        self.assertTrue(all("attack_prob" in entry for entry in direct["timeline"]))
        self.assertEqual(direct["overall_risk"], max(entry["attack_prob"] for entry in future))
        self.assertEqual(body["overall_risk"], direct["overall_risk"])
        self.assertIsInstance(direct["explanation"], list)
        self.assertEqual(direct["method"], "linear")
        self.assertIsInstance(body["explanation"], list)
        self.assertEqual(body["method"], "linear")
        observed_attack = [entry["attack_prob"] for entry in direct["timeline"] if entry["observed"] and entry["stage"] != "benign"]
        self.assertGreater(max(observed_attack), direct["overall_risk"])

    def test_cic_forecast_uses_lstm_and_not_synthetic_baseline(self):
        response = self.client.post(
            "/api/forecast/cicids?horizon_k=3",
            files={"file": ("sample.csv", io.BytesIO(_cic_csv()), "text/csv")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["model"], CICIDS)
        self.assertGreaterEqual(body["windows"], 3)
        allowed = set(CIC_SUPPORTED_STAGES)
        for entry in body["timeline"]:
            self.assertIn(entry["stage"], allowed)
        self.assertTrue(any(not entry["observed"] for entry in body["timeline"]))

        refused = self.client.post(
            "/api/forecast?horizon_k=3",
            files={"file": ("sample.csv", io.BytesIO(_cic_csv()), "text/csv")},
        )
        self.assertEqual(refused.status_code, 400)
        self.assertIn("/api/forecast/cicids", refused.json()["detail"])

    def test_cic_mode_does_not_fall_back_when_lstm_is_missing(self):
        fc._cache["cic_world"] = None
        frame = make_windows(n_episodes=1, seed=3)
        features = frame[FEATURES].iloc[:12].reset_index(drop=True)
        times = list(pd.date_range("2018-02-14 10:00", periods=len(features), freq="min"))
        with self.assertRaises(RuntimeError) as caught:
            fc.forecast(features, times, K=3, mode=CICIDS)
        self.assertIn("not used as a fallback", str(caught.exception))

    def test_cic_future_matches_lstm_rollout_not_logistic_repeat(self):
        captured = {}

        class Recorder:
            def rollout(self, windows, k):
                captured["windows"] = np.asarray(windows, dtype=float)
                captured["k"] = k
                probs = np.zeros((k, len(STAGES)))
                probs[:, STAGES.index("lateral_movement")] = 1.0
                return probs

        fc._cache["cic"] = fc._cic_baseline()
        fc._cache["cic_world"] = Recorder()
        saved = list(fc._cache["cic"]["features"])
        raw = np.arange(len(saved) * 6, dtype=float).reshape(6, len(saved))
        features = pd.DataFrame(raw, columns=saved)
        times = list(pd.date_range("2018-03-01 09:00", periods=len(features), freq="min"))
        body = fc.forecast(features, times, K=3, mode=CICIDS)
        self.assertEqual(body["model"], CICIDS)
        self.assertTrue(np.allclose(captured["windows"], raw))
        self.assertEqual(captured["k"], 3)
        future = [entry["stage"] for entry in body["timeline"] if not entry["observed"]]
        self.assertEqual(future, ["lateral_movement", "lateral_movement", "lateral_movement"])
        self.assertTrue((MODELS_DIR / "baseline.joblib").is_file())

    def test_cic_overall_risk_keeps_observed_attack_probability_when_future_is_benign(self):
        class Scaler:
            def transform(self, values):
                return np.asarray(values, dtype=float)

        class CurrentStage:
            classes_ = np.array([0, STAGES.index("lateral_movement")])
            coef_ = np.zeros((2, len(FEATURES)))

            def predict_proba(self, values):
                rows = np.tile([0.97, 0.03], (len(values), 1))
                rows[-1] = [0.02, 0.98]
                return rows

        class BenignFuture:
            def rollout(self, windows, k):
                probs = np.zeros((k, len(STAGES)))
                probs[:, STAGES.index("benign")] = 1.0
                return probs

        fc._cache["cic"] = {
            "scaler": Scaler(),
            "models": {0: CurrentStage()},
            "features": list(FEATURES),
        }
        fc._cache["cic_world"] = BenignFuture()
        features = pd.DataFrame(np.zeros((4, len(FEATURES))), columns=FEATURES)
        times = list(pd.date_range("2018-03-01 12:56", periods=len(features), freq="min"))
        body = fc.forecast(features, times, K=3, mode=CICIDS)
        future = [entry for entry in body["timeline"] if not entry["observed"]]
        observed_attack = [entry for entry in body["timeline"] if entry["observed"] and entry["stage"] != "benign"]
        self.assertEqual([entry["stage"] for entry in future], ["benign", "benign", "benign"])
        self.assertEqual(observed_attack[-1]["stage"], "lateral_movement")
        self.assertEqual(observed_attack[-1]["prob"], 0.98)
        self.assertEqual(observed_attack[-1]["attack_prob"], 0.98)
        self.assertTrue(all(entry["attack_prob"] == 0.0 for entry in future))
        self.assertEqual(body["overall_risk"], 0.0)
        self.assertEqual(body["observed_attack_probability"], 0.98)
        self.assertEqual(body["explanation"], [])
        self.assertIsNone(body["method"])

    def test_observed_attack_probability_includes_windows_outside_the_timeline(self):
        class Scaler:
            def transform(self, values):
                return np.asarray(values, dtype=float)

        class CurrentStage:
            classes_ = np.array([0, STAGES.index("lateral_movement")])
            coef_ = np.zeros((2, len(FEATURES)))

            def predict_proba(self, values):
                rows = np.tile([0.99, 0.01], (len(values), 1))
                rows[0] = [0.016, 0.984]
                return rows

        class BenignFuture:
            def rollout(self, windows, k):
                probs = np.zeros((k, len(STAGES)))
                probs[:, STAGES.index("benign")] = 1.0
                return probs

        fc._cache["cic"] = {
            "scaler": Scaler(),
            "models": {0: CurrentStage()},
            "features": list(FEATURES),
        }
        fc._cache["cic_world"] = BenignFuture()
        features = pd.DataFrame(np.zeros((14, len(FEATURES))), columns=FEATURES)
        times = list(pd.date_range("2018-03-01 09:00", periods=len(features), freq="min"))
        body = fc.forecast(features, times, K=3, mode=CICIDS)
        visible = [entry for entry in body["timeline"] if entry["observed"]]
        self.assertTrue(visible)
        self.assertTrue(all(entry["stage"] == "benign" for entry in visible))
        self.assertEqual(body["observed_attack_probability"], 0.984)
        self.assertEqual(body["overall_risk"], 0.0)
        self.assertTrue(all(entry["attack_prob"] == 0.0 for entry in body["timeline"] if not entry["observed"]))
        self.assertTrue(all(entry["stage"] == "benign" for entry in body["timeline"] if not entry["observed"]))

        class AttackFuture:
            def rollout(self, windows, k):
                probs = np.zeros((k, len(STAGES)))
                probs[:, STAGES.index("lateral_movement")] = 0.7
                probs[:, STAGES.index("benign")] = 0.3
                return probs

        class BenignNow(CurrentStage):
            def predict_proba(self, values):
                return np.tile([0.99, 0.01], (len(values), 1))

        fc._cache["cic"]["models"][0] = BenignNow()
        fc._cache["cic_world"] = AttackFuture()
        benign = fc.forecast(features, times, K=3, mode=CICIDS)
        self.assertIsNone(benign["observed_attack_probability"])
        self.assertEqual(benign["overall_risk"], 0.7)
        self.assertTrue(all(entry["attack_prob"] == 0.7 for entry in benign["timeline"] if not entry["observed"]))

    def test_benchmark_returns_stable_keys(self):
        body = self.client.get("/api/benchmark").json()
        required = {"models", "horizons", "metrics", "split", "notes", "diagnostics"}
        self.assertTrue(required <= set(body))
        diagnostics = body["diagnostics"]
        self.assertIsNotNone(diagnostics)
        self.assertEqual(
            set(diagnostics),
            {"model", "seed", "horizon", "threshold", "benign_test_rows", "false_positives", "groups", "volume_matched", "near_attack"},
        )
        self.assertEqual(set(diagnostics["groups"]), {"ever_attack", "never_attack"})
        self.assertEqual(set(diagnostics["near_attack"]), {"<=3", "4-30", ">30", "no_attack"})
        self.assertNotIn("subnets", diagnostics)
        self.assertNotIn("deciles", diagnostics)
        archived = MODELS_DIR / "archive"
        top = [
            path for path in MODELS_DIR.iterdir()
            if path.is_file() and path.name.startswith("benchmark") and path.suffix == ".json"
        ]
        if not top:
            self.assertEqual(set(body), required)
            self.assertEqual(body["models"], [])
            self.assertEqual(body["horizons"], [])
            self.assertEqual(body["metrics"], [])
            self.assertEqual(body["split"], {})
            self.assertTrue(any(note.get("text") == "No benchmark yet" for note in body["notes"]))
        else:
            self.assertTrue((MODELS_DIR / "benchmark_v3.json").is_file())
            self.assertTrue(body["metrics"])
            text = " ".join(note.get("text", "") for note in body["notes"]).lower()
            self.assertIn("proxy", text)
            self.assertIn("excluded", text)
        for name in ("benchmark.json", "benchmark_cicids2018.json", "benchmark_world_model_cicids2018.json"):
            self.assertTrue((archived / name).is_file(), name)
            self.assertFalse((MODELS_DIR / name).is_file(), name)

    def test_cic_upload_names_missing_columns(self):
        raw = b"Timestamp,Label\n14/02/2018 10:00:00,Benign\n"
        response = self.client.post(
            "/api/forecast/cicids",
            files={"file": ("partial.csv", io.BytesIO(raw), "text/csv")},
        )
        self.assertEqual(response.status_code, 422, response.text)
        detail = response.json()["detail"]
        self.assertIn("Missing required columns:", detail)
        self.assertIn("flow duration", detail)
        self.assertIn("dst port", detail)

        windowed = b"n_flows,log_mean_duration\n1,0.1\n2,0.2\n3,0.3\n"
        refused = self.client.post(
            "/api/forecast",
            files={"file": ("windows.csv", io.BytesIO(windowed), "text/csv")},
        )
        self.assertEqual(refused.status_code, 422, refused.text)
        self.assertIn("log_mean_iat", refused.json()["detail"])


if __name__ == "__main__":
    unittest.main()
