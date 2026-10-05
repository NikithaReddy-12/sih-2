"""Host-window selection, labels, and sequence silence. No full CSV."""
import unittest

import numpy as np
import pandas as pd

from ml.config import V3_STAGES
from ml.host_train import _cap_anchors, block_bootstrap, network_alarm, stack_host
from ml.host_v3 import (
    CONTEXT_FEATURES,
    CONCENTRATION_FEATURES,
    FLOW_FEATURES,
    HOST_FEATURES,
    PACKET_FEATURES,
    apply_network_split,
    fill_split_gaps,
    host_anchors,
    label_host_rows,
    select_hosts,
)


def _counts(rows):
    frame = pd.DataFrame(rows)
    for column in ("n_benign", "n_initial", "n_lateral", "n_c2", "n_excluded", "n_other"):
        if column not in frame:
            frame[column] = 0
    return frame


class HostV3Tests(unittest.TestCase):
    def test_select_hosts_uses_flow_count_not_label(self):
        rows = [{"window": 1, "src": index, "n": 10, "n_initial": 0} for index in range(500)]
        rows.append({"window": 1, "src": 999, "n": 4, "n_initial": 4})
        rows.append({"window": 1, "src": 1000, "n": 2, "n_initial": 2})
        selected = select_hosts(_counts(rows), min_flows=3, top=500)
        self.assertNotIn(999, set(selected["src"]))
        self.assertNotIn(1000, set(selected["src"]))
        self.assertEqual(len(selected), 500)
        self.assertEqual(int(selected["n_initial"].sum()), 0)

    def test_label_requires_half_and_drops_dos(self):
        frame = _counts([
            {"window": 1, "src": 1, "n": 10, "n_initial": 5},
            {"window": 1, "src": 2, "n": 10, "n_initial": 4},
            {"window": 1, "src": 3, "n": 10, "n_excluded": 6, "n_initial": 4},
            {"window": 1, "src": 4, "n": 10, "n_lateral": 5},
            {"window": 1, "src": 5, "n": 8, "n_c2": 4},
        ])
        labeled = label_host_rows(frame)
        stages = list(labeled["stage"])
        self.assertEqual(stages, ["initial_access", "benign", "dropped", "lateral_movement", "command_and_control"])

    def test_feature_names_have_no_raw_address(self):
        joined = " ".join(HOST_FEATURES).lower()
        self.assertNotIn("ipv4", joined)
        self.assertNotIn("src", joined)
        self.assertIn("active", HOST_FEATURES)
        self.assertEqual(HOST_FEATURES[:len(FLOW_FEATURES)], FLOW_FEATURES)
        self.assertTrue(set(PACKET_FEATURES).issubset(HOST_FEATURES))
        self.assertTrue(set(CONCENTRATION_FEATURES).issubset(HOST_FEATURES))
        self.assertTrue(set(CONTEXT_FEATURES).issubset(HOST_FEATURES))
        self.assertIn("log1p_window_flows", CONTEXT_FEATURES)
        self.assertIn("active_hosts", CONTEXT_FEATURES)
        self.assertEqual(len(HOST_FEATURES), len(set(HOST_FEATURES)))

    def test_missing_host_slot_still_anchors_when_the_split_covers_it(self):
        split_map = {slot: "train" for slot in range(1, 20)}
        frame = pd.DataFrame({
            "src": [1],
            "window": [10],
            "stage": ["benign"],
            "split": ["train"],
        })
        anchors = host_anchors(frame, split_map, seq_len=10, future=5)
        self.assertEqual(list(anchors["train"]), [0])
        split_map[3] = "purge"
        anchors = host_anchors(frame, split_map, seq_len=10, future=5)
        self.assertEqual(len(anchors["train"]), 0)

    def test_gap_fill_stays_inside_one_split(self):
        filled = fill_split_gaps({1: "train", 4: "train", 6: "test"}, window_s=60)
        self.assertEqual(filled[2], "train")
        self.assertEqual(filled[3], "train")
        self.assertNotIn(5, filled)

    def test_silence_is_a_zero_vector(self):
        scaled = np.array([[3.0, 1.0]], dtype=np.float32)
        hosts = np.array([7], dtype=np.uint32)
        windows = np.array([10], dtype=np.int64)
        codes = np.array([V3_STAGES.index("benign")], dtype=np.int64)
        pos = {(7, 10): 0}
        seqs, nxt, ys = stack_host(scaled, hosts, windows, codes, np.array([0]), pos, seq_len=3, k=2)
        self.assertTrue(np.array_equal(seqs[0, 0], [0.0, 0.0]))
        self.assertTrue(np.array_equal(seqs[0, 1], [0.0, 0.0]))
        self.assertTrue(np.array_equal(seqs[0, 2], [3.0, 1.0]))
        self.assertTrue(np.array_equal(nxt[0], [0.0, 0.0]))
        self.assertEqual(list(ys[0]), [0, 0, 0])

    def test_dropped_rows_do_not_keep_a_split(self):
        frame = pd.DataFrame({
            "src": [1, 2],
            "window": [10, 10],
            "stage": ["dropped", "benign"],
        })
        out = apply_network_split(frame, {10: "train"})
        self.assertEqual(list(out["stage"]), ["benign"])
        self.assertEqual(list(out["split"]), ["train"])

    def test_network_alarm_uses_the_max_host_and_lead_time(self):
        windows = np.array([10, 10, 11])
        future = np.array([
            [0.9, 0.1],
            [0.1, 0.1],
            [0.0, 0.0],
        ])
        scored = network_alarm(windows, future, {12}, k=2)
        self.assertEqual(scored["n"], 2)
        self.assertAlmostEqual(scored["precision"], 1.0)
        self.assertAlmostEqual(scored["recall"], 0.5)
        self.assertAlmostEqual(scored["fpr"], 0.0)
        self.assertAlmostEqual(scored["lead"], 1.0)

    def test_cap_anchors_keeps_rare_classes_under_the_cap(self):
        index = np.arange(100)
        codes = np.array([0] * 90 + [1] * 9 + [2])
        capped = _cap_anchors(index, codes, 20, 0)
        self.assertLessEqual(len(capped), 20)
        self.assertEqual(set(np.unique(codes[capped])), {0, 1, 2})
        self.assertTrue(np.all(capped[:-1] <= capped[1:]))

    def test_block_bootstrap_requires_the_interval_above_zero(self):
        labels = np.array([0, 0, 1, 1, 0, 0, 1, 1])
        blocks = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        better = block_bootstrap(labels, labels, 1 - labels, blocks, n_boot=40, seed=0)
        tied = block_bootstrap(labels, labels, labels, blocks, n_boot=40, seed=0)
        self.assertTrue(better["beats"])
        self.assertGreater(better["low"], 0.0)
        self.assertFalse(tied["beats"])


if __name__ == "__main__":
    unittest.main()
