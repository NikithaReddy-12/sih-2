"""NetFlow-V3 labelling, windows, and artifact feature lists. No full CSV."""
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd

from ml.config import FEATURES, FLOW_FEATURES, PACKET_FEATURES, V3_STAGES
from ml.model_v3 import load_lstm, save_lstm, WorldV3
from ml.netflow_v3 import (
    _cache_paths,
    _finalize_windows,
    attack_bucket,
    assign_splits,
    modeling_frame,
    passes_date_gate,
    prepare_chunk,
    sequence_anchors,
)
from sklearn.preprocessing import StandardScaler


def _flows(rows):
    frame = pd.DataFrame(rows)
    return frame


class NetFlowV3Tests(unittest.TestCase):
    def test_attack_strings_and_date_gate(self):
        self.assertEqual(attack_bucket("FTP-BruteForce"), "initial_access")
        self.assertEqual(attack_bucket("SSH-Bruteforce"), "initial_access")
        self.assertEqual(attack_bucket("Infilteration"), "lateral_movement")
        self.assertEqual(attack_bucket("Infiltration"), "lateral_movement")
        self.assertEqual(attack_bucket("Bot"), "command_and_control")
        self.assertEqual(attack_bucket("Benign"), "benign")
        self.assertEqual(attack_bucket("DDOS_attack-HOIC"), "excluded")
        self.assertEqual(attack_bucket("DDoS_attacks-LOIC-HTTP"), "excluded")
        self.assertEqual(attack_bucket("DoS_attacks-Hulk"), "excluded")
        self.assertEqual(attack_bucket("Brute_Force_-Web"), "excluded")
        self.assertEqual(attack_bucket("Brute_Force_-XSS"), "excluded")
        self.assertEqual(attack_bucket("SQL_Injection"), "excluded")
        ok, span = passes_date_gate(1518611287705, 1519999465524)
        self.assertTrue(ok, span)
        self.assertIn("2018-02-14", span)
        self.assertIn("2018-03-02", span)
        self.assertFalse(passes_date_gate(1510000000000, 1518611287705)[0])

    def test_feature_lists_have_no_time_of_day(self):
        self.assertEqual(FEATURES, FLOW_FEATURES + PACKET_FEATURES)
        self.assertTrue(set(FLOW_FEATURES).isdisjoint(PACKET_FEATURES))
        for name in FEATURES:
            self.assertNotIn("hour", name)
            self.assertNotIn("time_of_day", name)

    def test_window_label_drop_and_proxy_stage(self):
        def row(attack, src, dst="10.0.0.2", port=80, proto=6, flags=2, n=1):
            return {
                "FLOW_START_MILLISECONDS": 1518611287705,
                "IPV4_SRC_ADDR": src,
                "IPV4_DST_ADDR": dst,
                "L4_DST_PORT": port,
                "PROTOCOL": proto,
                "IN_BYTES": 100,
                "IN_PKTS": 2,
                "OUT_BYTES": 40,
                "OUT_PKTS": 1,
                "TCP_FLAGS": flags,
                "FLOW_DURATION_MILLISECONDS": 20,
                "MIN_TTL": 64,
                "MAX_TTL": 64,
                "RETRANSMITTED_IN_PKTS": 0,
                "RETRANSMITTED_OUT_PKTS": 0,
                "TCP_WIN_MAX_IN": 1000,
                "TCP_WIN_MAX_OUT": 500,
                "SRC_TO_DST_IAT_MAX": 10,
                "SRC_TO_DST_IAT_AVG": 5,
                "SRC_TO_DST_IAT_STDDEV": 1,
                "DST_TO_SRC_IAT_MAX": 8,
                "DST_TO_SRC_IAT_AVG": 4,
                "DST_TO_SRC_IAT_STDDEV": 1,
                "Attack": attack,
            }

        benign = [row("Benign", "10.0.0.1") for _ in range(9)]
        brute = benign + [row("FTP-BruteForce", "10.0.0.9", port=22)]
        dos = [row("DoS_attacks-Hulk", f"10.0.0.{i}", port=80) for i in range(2)] + [row("Benign", "10.0.0.3")]
        scan_rows = [row("Benign", "10.1.0.8", port=port) for port in (1, 2, 3)]
        prepared = prepare_chunk(pd.DataFrame(brute), 60_000)
        table = _finalize_windows([prepared["numeric"]], [prepared["src"]], [prepared["dst"]], [prepared["ports"]], [prepared["scan"]], 60_000, 0.05)
        self.assertEqual(table.loc[0, "stage"], "initial_access")
        prepared_dos = prepare_chunk(pd.DataFrame(dos), 60_000)
        dropped = _finalize_windows(
            [prepared_dos["numeric"]], [prepared_dos["src"]], [prepared_dos["dst"]],
            [prepared_dos["ports"]], [prepared_dos["scan"]], 60_000, 0.05,
        )
        self.assertEqual(dropped.loc[0, "stage"], "dropped")
        prepared_scan = prepare_chunk(pd.DataFrame(scan_rows), 60_000)
        scanned = _finalize_windows(
            [prepared_scan["numeric"]], [prepared_scan["src"]], [prepared_scan["dst"]],
            [prepared_scan["ports"]], [prepared_scan["scan"]], 60_000, 0.05,
        )
        self.assertEqual(int(scanned.loc[0, "port_scan"]), 3)
        self.assertEqual(int(scanned.loc[0, "uniq_src"]), 1)
        self.assertEqual(int(scanned.loc[0, "uniq_dport"]), 3)
        self.assertAlmostEqual(float(scanned.loc[0, "syn_n"] / scanned.loc[0, "tcp_n"]), 1.0)

    def test_split_purge_and_gap(self):
        start = 1518611280000
        rows = []
        for index in range(100):
            rows.append({
                "window_start_ms": start + index * 60_000,
                "day": "2018-02-14",
                "stage": "benign",
                "n": 1,
            })
        # A hole longer than 10 minutes breaks sequences.
        rows[40]["window_start_ms"] = rows[39]["window_start_ms"] + 11 * 60_000
        frame = assign_splits(pd.DataFrame(rows), purge=15)
        self.assertEqual(int((frame["split"] == "train").sum()), 45)
        self.assertEqual(int((frame["split"] == "val").sum()), 0)
        self.assertEqual(int((frame["split"] == "test").sum()), 25)
        long = []
        base = 1518611280000
        for index in range(400):
            stage = "initial_access" if 300 <= index < 340 else "benign"
            long.append({
                "window_start_ms": base + index * 60_000,
                "day": "2018-02-14",
                "stage": stage,
                "n": 1,
            })
        modeled = assign_splits(pd.DataFrame(long), purge=15)
        anchors = sequence_anchors(modeled, "test", seq_len=10, future=5)
        self.assertGreater(len(anchors), 0)
        # No anchor may use a pair more than 10 minutes apart. These rows are contiguous, so all pass that rule.
        self.assertTrue(np.all(np.diff(modeled.loc[anchors, "window_start_ms"]) >= 0))

    def test_lstm_artifact_keeps_its_own_feature_list(self):
        features = ["log1p_n_flows", "syn_ratio"]
        model = WorldV3(len(features), 4, hidden=8, embedding=4)
        scaler = StandardScaler().fit(np.ones((4, 2)))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tiny.pt"
            save_lstm(path, model, scaler, {"log1p_n_flows": 3.0}, features, seed=0, kind="lstm")
            loaded = load_lstm(path)
        self.assertEqual(loaded["features"], features)
        self.assertEqual(loaded["config"]["n_features"], 2)
        self.assertNotEqual(loaded["features"], FEATURES)

    def test_attack_span_puts_tail_in_test_and_splits_are_disjoint(self):
        base = 1518611280000
        rows = []
        for index in range(400):
            stage = "initial_access" if 50 <= index <= 249 else "benign"
            rows.append({
                "window_start_ms": base + index * 60_000,
                "day": "2018-02-14",
                "stage": stage,
                "n": 1,
            })
        frame = assign_splits(pd.DataFrame(rows), purge=15)
        self.assertTrue((frame.loc[:49, "split"] == "train").all())
        self.assertTrue((frame.loc[250:, "split"] == "test").all())
        span = frame.iloc[50:250]
        self.assertEqual(int((span["split"] == "train").sum()), 105)
        self.assertEqual(int((span["split"] == "val").sum()), 15)
        self.assertEqual(int((span["split"] == "test").sum()), 50)
        self.assertEqual(len(frame), len(frame.drop_duplicates("window_start_ms")))
        self.assertTrue(set(frame["split"]) <= {"train", "val", "test", "purge"})

    def test_real_cache_has_every_stage_in_train_val_and_test(self):
        cache, _meta = _cache_paths(60)
        self.assertTrue(cache.is_file(), cache)
        modeled = modeling_frame(pd.read_csv(cache))
        keys = list(zip(modeled["day"], modeled["window_start_ms"]))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(set(modeled["split"]) <= {"train", "val", "test", "purge"})
        for stage in V3_STAGES:
            for split in ("train", "val", "test"):
                count = int(((modeled["stage"] == stage) & (modeled["split"] == split)).sum())
                self.assertGreater(count, 0, f"{stage} missing from {split}")


if __name__ == "__main__":
    unittest.main()
