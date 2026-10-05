"""Small synthetic PCAP ingestion and host-route tests."""
import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import PcapWriter
from fastapi.testclient import TestClient

from main import app
from ml.host_v3 import PASS2_COLS
from ml.host_v3 import aggregate_host_windows
from ml.pcap_ingest import pcap_to_frame


def _write_capture(path: Path) -> None:
    writer = PcapWriter(str(path), sync=True)
    base = 1_700_000_000.0
    for window in range(20):
        timestamp = base + window * 60
        for host, port_base in (("10.0.0.1", 2000), ("10.0.0.9", 4000)):
            for offset in range(3):
                packet = Ether() / IP(src=host, dst="10.0.1.1", ttl=64) / TCP(
                    sport=port_base + offset,
                    dport=80 + window * 3 + offset,
                    flags="S",
                    seq=window * 100 + offset,
                    window=4096,
                )
                packet.time = timestamp + offset * 0.01
                writer.write(packet)
        if window == 0:
            retrans = Ether() / IP(src="10.0.0.1", dst="10.0.1.2", ttl=63) / TCP(
                sport=9000, dport=443, flags="PA", seq=7, window=2048
            ) / b"payload"
            retrans.time = timestamp + 0.1
            writer.write(retrans)
            retrans.time = timestamp + 0.2
            writer.write(retrans)
            writer.write(Ether() / ARP(pdst="10.0.0.1"))
    writer.close()


class PcapIngestTests(unittest.TestCase):
    def test_three_concurrent_ten_minute_connections_retain_host_windows(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "steady.pcap"
            writer = PcapWriter(str(path), sync=True)
            base = 1_700_000_000.0
            for window in range(10):
                for connection in range(3):
                    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(
                        sport=4000 + connection, dport=443, flags="PA", seq=window,
                    ) / b"steady"
                    packet.time = base + window * 60 + connection * 0.1 + 1
                    writer.write(packet)
            writer.close()
            frame, _stats = pcap_to_frame(path)
            csv_path = Path(tmp) / "steady.csv"
            frame.to_csv(csv_path, index=False)
            table, meta, _flows = aggregate_host_windows(csv_path, window_s=60, keep_flows=True)
        self.assertEqual(len(table), 10)
        self.assertEqual(meta["min_flows_dropped_host_windows"], 0)

    def test_ten_minute_connection_splits_at_active_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "long.pcap"
            writer = PcapWriter(str(path), sync=True)
            base = 1_700_000_000.0
            for offset in range(10):
                packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=4000, dport=443, flags="PA", seq=offset)
                packet.time = base + offset * 60 + 1
                writer.write(packet)
            writer.close()
            frame, stats = pcap_to_frame(path)
            csv_path = Path(tmp) / "long.csv"
            frame.to_csv(csv_path, index=False)
            table, meta, _flows = aggregate_host_windows(csv_path, window_s=60, keep_flows=True)
        self.assertEqual(stats["flows"], 10)
        self.assertEqual(int((frame["FLOW_START_MILLISECONDS"] // 60000).nunique()), 10)
        self.assertEqual(len(table), 0)
        self.assertEqual(meta["min_flows_dropped_host_windows"], 10)

    def test_streaming_capture_builds_host_columns_and_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.pcap"
            _write_capture(path)
            frame, stats = pcap_to_frame(path)
        self.assertTrue(set(PASS2_COLS) <= set(frame.columns))
        self.assertGreaterEqual(len(frame), 120)
        self.assertEqual(stats["skipped_packets"], 1)
        self.assertGreater(stats["flows"], 120)
        self.assertGreaterEqual(int(frame["RETRANSMITTED_OUT_PKTS"].max()), 1)
        self.assertGreaterEqual(int(frame["FLOW_DURATION_MILLISECONDS"].max()), 100)
        self.assertTrue((frame["SRC_TO_DST_IAT_AVG"] >= 0).all())

    def test_host_route_accepts_synthetic_pcap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "scan.pcapng"
            _write_capture(path)
            response = TestClient(app).post(
                "/api/forecast/netflow-v3-host?horizon_k=3",
                files={"file": (path.name, path.read_bytes(), "application/vnd.tcpdump.pcap")},
            )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertIn("PCAP features approximate NetFlow-V3 training features.", body["notes"])

    def test_short_pcap_returns_clear_422(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "short.pcap"
            writer = PcapWriter(str(path), sync=True)
            writer.write(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80))
            writer.close()
            response = TestClient(app).post(
                "/api/forecast/netflow-v3-host",
                files={"file": (path.name, path.read_bytes(), "application/vnd.tcpdump.pcap")},
            )
        self.assertEqual(response.status_code, 422)
        self.assertIn("too short or too sparse", response.json()["detail"])

    def test_recon_exfil_demo_route_returns_separate_heuristics(self):
        path = Path(__file__).resolve().parents[1] / "samples" / "recon_exfil_demo.pcap"
        response = TestClient(app).post(
            "/api/forecast/netflow-v3-host?horizon_k=3",
            files={"file": (path.name, path.read_bytes(), "application/vnd.tcpdump.pcap")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        stages = {hit["stage"] for hit in body["heuristic_hosts"]}
        self.assertIn("reconnaissance", stages)
        self.assertIn("exfiltration", stages)
        self.assertTrue(all(hit["source"] == "heuristic" for hit in body["heuristic_hosts"]))


if __name__ == "__main__":
    unittest.main()
