import unittest

import pandas as pd

from ml.heuristic_stages import detect_heuristic_stages


FEATURE_COLUMNS = {
    "log1p_port_scan_score": 0.0,
    "log1p_uniq_dst_ports": 0.0,
    "top_dst_port_share": 1.0,
    "small_flow_share": 0.0,
    "no_response_share": 0.0,
    "log1p_out_in_byte_ratio": 0.0,
    "mean_log_out_bytes": 0.0,
    "top_dst_ip_share": 0.0,
    "dst_is_private": False,
}


def _rows(host: int, windows: range, recon: set[int] = set(), exfil: set[int] = set()):
    result = []
    for window in windows:
        row = {"src": host, "window": window, **FEATURE_COLUMNS}
        if window in recon:
            row.update({
                "log1p_port_scan_score": 4.0,
                "log1p_uniq_dst_ports": 4.0,
                "top_dst_port_share": 0.01,
                "small_flow_share": 1.0,
                "no_response_share": 1.0,
            })
        if window in exfil:
            row.update({
                "log1p_out_in_byte_ratio": 3.0,
                "mean_log_out_bytes": 10.0,
                "top_dst_ip_share": 1.0,
                "dst_is_private": True,
            })
        result.append(row)
    return result


class HeuristicStageTests(unittest.TestCase):
    def test_recon_fires_after_two_of_three_windows(self):
        result = detect_heuristic_stages(pd.DataFrame(_rows(1, range(1, 4), recon={1, 3})))
        self.assertEqual([hit["stage"] for hit in result["hosts"]], ["reconnaissance"])
        self.assertEqual(result["hosts"][0]["source"], "heuristic")
        self.assertEqual(result["hosts"][0]["mitre_id"], "TA0043")

    def test_recon_does_not_fire_on_one_window(self):
        result = detect_heuristic_stages(pd.DataFrame(_rows(1, range(1, 4), recon={3})))
        self.assertEqual(result["hosts"], [])

    def test_single_window_500_port_burst_fires(self):
        rows = _rows(1, range(1, 2), recon={1})
        rows[0]["log1p_uniq_dst_ports"] = 6.0
        result = detect_heuristic_stages(pd.DataFrame(rows))
        self.assertEqual(result["hosts"][0]["rule_values"]["mode"], "single_window_burst")
        self.assertLessEqual(result["hosts"][0]["score"], 0.333333)

    def test_exfil_requires_three_consecutive_windows(self):
        fires = detect_heuristic_stages(pd.DataFrame(_rows(2, range(1, 6), exfil={1, 2, 3})))
        self.assertEqual([hit["stage"] for hit in fires["hosts"]], ["exfiltration"])
        self.assertEqual(fires["hosts"][0]["mitre_id"], "TA0010")
        self.assertEqual(fires["hosts"][0]["rule_values"]["dst_is_private"], [True, True, True])
        misses = detect_heuristic_stages(pd.DataFrame(_rows(2, range(1, 6), exfil={1, 3, 5})))
        self.assertEqual(misses["hosts"], [])

    def test_common_benign_shape_does_not_fire(self):
        result = detect_heuristic_stages(pd.DataFrame(_rows(3, range(1, 8))))
        self.assertEqual(result["hosts"], [])


if __name__ == "__main__":
    unittest.main()
