import io
import json
import os
import tempfile
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse

from ml import forecast as fc
from ml.cicids import _header, load_capture, missing_required_columns, windows_to_frame
from ml.features import FEATURES, flows_to_windows
from ml.forecast import CICIDS, NETFLOW_V3_HOST, SYNTHETIC
from ml.host_forecast import (
    REPLAY_NOTE,
    forecast_host_file,
    missing_required_columns as host_missing_columns,
    read_header,
)
from ml.pcap_ingest import pcap_to_frame
from ml.synth import make_windows
from schemas.forecast import ForecastResponse

router = APIRouter(tags=["Forecast"])
SAMPLES_DIR = Path(__file__).resolve().parents[2] / "samples"
SAMPLE_SUFFIXES = {".csv", ".pcap", ".pcapng", ".gz", ".json", ".md"}
HOST_UPLOAD_LIMIT = 200 * 1024 * 1024


def _sample_allowed(name: str) -> bool:
    lower = name.lower()
    if lower.endswith(".csv.gz"):
        return True
    return Path(name).suffix.lower() in SAMPLE_SUFFIXES and not lower.endswith(".gz")


def _sample_path(name: str) -> Path:
    if Path(name).name != name or not _sample_allowed(name):
        raise HTTPException(404, "Sample not found.")
    path = SAMPLES_DIR / name
    if not path.is_file():
        raise HTTPException(404, "Sample not found.")
    return path


def _modernize_verdict(record: dict, block: dict) -> dict:
    labelled = {row["host"]: row for row in record.get("labelled_attackers") or []}
    flagged = block.get("flagged_hosts") or []
    stage_matched = sum(
        1 for row in flagged
        if row.get("label_stage") is not None and row.get("predicted_stage") == row.get("label_stage")
    )
    modern = dict(block)
    modern.pop("stage_match", None)
    modern["stage_matched"] = stage_matched
    modern["stage_total"] = len(labelled)
    modern["flagged_unlabelled"] = sum(1 for row in flagged if row.get("label_stage") is None)
    for row in modern.get("flagged_hosts") or []:
        row.pop("stage_match", None)
        row["stage_matched"] = row.get("predicted_stage") == row.get("label_stage") if row.get("label_stage") is not None else False
    return modern


def _modernize_ground_truth(payload: dict) -> dict:
    result = dict(payload)
    result["samples"] = {
        name: {
            **record,
            "current": _modernize_verdict(record, record.get("current") or {}),
            "forecast": _modernize_verdict(record, record.get("forecast") or {}),
        }
        for name, record in (payload.get("samples") or {}).items()
    }
    return result


@router.get("/api/samples")
def list_samples():
    if not SAMPLES_DIR.is_dir():
        return {"files": []}
    files = sorted(
        path.name for path in SAMPLES_DIR.iterdir()
        if path.is_file() and _sample_allowed(path.name)
    )
    ground_path = SAMPLES_DIR / "ground_truth.json"
    ground_truth = None
    if ground_path.is_file():
        ground_truth = _modernize_ground_truth(json.loads(ground_path.read_text(encoding="utf-8")))
    return {"files": files, "ground_truth": ground_truth}


@router.get("/api/samples/{name}")
def get_sample(name: str):
    path = _sample_path(name)
    return FileResponse(path, filename=path.name)


def _read_csv(raw: bytes) -> pd.DataFrame:
    try:
        frame = pd.read_csv(io.BytesIO(raw), low_memory=False)
    except Exception as exc:
        raise HTTPException(400, f"Could not read CSV: {exc}") from exc
    frame.columns = [str(column).strip() for column in frame.columns]
    return frame


@router.get("/api/forecast/status")
def status():
    return fc.model_info()


def _diagnostics():
    path = Path(__file__).resolve().parents[2] / "ml" / "models" / "diag_hosts.json"
    if not path.is_file():
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    groups = payload.get("groups") or {}
    return {
        key: payload.get(key)
        for key in ("model", "seed", "horizon", "threshold", "benign_test_rows", "false_positives")
    } | {
        "groups": {
            key: groups[key] for key in ("ever_attack", "never_attack") if key in groups
        },
        "volume_matched": payload.get("volume_matched"),
        "near_attack": payload.get("near_attack", groups.get("near_attack")),
    }


@router.get("/api/benchmark")
def get_benchmark():
    body = fc.benchmark()
    body["diagnostics"] = _diagnostics()
    return body


@router.get("/api/forecast/demo", response_model=ForecastResponse)
def demo(k: int = Query(3, ge=1, le=10)):
    """Synthetic episode scored only by baseline.joblib. The CIC LSTM is not used."""
    df = make_windows(n_episodes=1, seed=11)
    times = list(pd.date_range("2018-02-15 10:00", periods=len(df), freq="min"))
    cut = int(len(df) * 0.55)
    try:
        return fc.forecast(df.iloc[:cut][FEATURES].reset_index(drop=True), times[:cut], K=k, mode=SYNTHETIC)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post("/api/forecast/cicids", response_model=ForecastResponse)
async def post_cicids(file: UploadFile = File(...), horizon_k: int = Query(3, ge=1, le=10),
                      window_s: int = Query(60, ge=1)):
    """CICFlowMeter CSV. Observed stages use the CIC logistic baseline; futures use the LSTM."""
    name = (file.filename or "").lower()
    if name.endswith((".pcap", ".pcapng")):
        raise HTTPException(501, "PCAP upload is not enabled yet. Upload a CICFlowMeter CSV.")
    if not name.endswith(".csv"):
        raise HTTPException(400, "Upload a CIC-IDS-2018 CICFlowMeter .csv file.")
    raw = await file.read()
    fd, tmp_name = tempfile.mkstemp(suffix=".csv")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        try:
            header = _header(tmp)
        except StopIteration as exc:
            raise HTTPException(422, "Missing required columns: the CSV has no header.") from exc
        missing = missing_required_columns(header)
        if missing:
            raise HTTPException(422, "Missing required columns: " + ", ".join(missing) + ".")
        try:
            windows, stats = load_capture(tmp, window_s=window_s)
            frame = windows_to_frame(windows, stats["source_ip_column"], stats["destination_ip_column"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    finally:
        tmp.unlink(missing_ok=True)
    if len(frame) < 3:
        raise HTTPException(422, "Need at least 3 time windows of traffic to forecast.")
    try:
        return fc.forecast(frame[FEATURES], list(frame["window_start"]), K=horizon_k, mode=CICIDS)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc


@router.post("/api/forecast/netflow-v3-host", response_model=ForecastResponse)
async def post_netflow_v3_host(file: UploadFile = File(...), horizon_k: int = Query(5, ge=1, le=5)):
    """NetFlow-V3 CSV or PCAP scored by the host LSTM (seed 0)."""
    name = file.filename or ""
    lower = name.lower()
    is_pcap = lower.endswith((".pcap", ".pcapng"))
    if not (lower.endswith(".csv") or lower.endswith(".csv.gz") or is_pcap):
        raise HTTPException(400, "Upload a NetFlow-V3 .csv, .csv.gz, .pcap, or .pcapng file.")
    raw = await file.read()
    if len(raw) > HOST_UPLOAD_LIMIT:
        raise HTTPException(413, "Upload exceeds 200 MB.")
    suffix = ".pcap" if is_pcap else ".csv.gz" if lower.endswith(".csv.gz") else ".csv"
    fd, tmp_name = tempfile.mkstemp(suffix=suffix)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
        if is_pcap:
            try:
                frame, pcap_stats = pcap_to_frame(tmp)
            except Exception as exc:
                raise HTTPException(422, f"Could not read PCAP: {exc}") from exc
            if frame.empty:
                raise HTTPException(422, "PCAP contained no IPv4 flows.")
            windows = int((frame["FLOW_START_MILLISECONDS"] // 60000).nunique())
            host_window_counts = frame.groupby([
                frame["FLOW_START_MILLISECONDS"] // 60000,
                "IPV4_SRC_ADDR",
            ]).size()
            if windows < 10:
                raise HTTPException(422, f"PCAP is too short or too sparse: it contains {windows} one-minute windows; at least 10 are required for host history.")
            if not host_window_counts.ge(3).any():
                raise HTTPException(422, f"PCAP is too short or too sparse: {len(host_window_counts)} host-windows were found, but none has the required 3 flows per host-window.")
            csv_fd, csv_name = tempfile.mkstemp(suffix=".csv")
            os.close(csv_fd)
            csv_tmp = Path(csv_name)
            try:
                frame.to_csv(csv_tmp, index=False)
                body = forecast_host_file(csv_tmp, k=horizon_k, replay=False)
            finally:
                csv_tmp.unlink(missing_ok=True)
            body.setdefault("notes", []).append("PCAP features approximate NetFlow-V3 training features.")
            body.setdefault("notes", []).append(f"PCAP parser skipped {pcap_stats['skipped_packets']} non-IPv4 packets.")
        else:
            header = read_header(tmp)
            if not header:
                raise HTTPException(422, "Missing required columns: the CSV has no header.")
            missing = host_missing_columns(header)
            if missing:
                raise HTTPException(422, "Missing required columns: " + ", ".join(missing) + ".")
            try:
                body = forecast_host_file(tmp, k=horizon_k, replay="kill_chain_replay" in lower)
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from exc
            except RuntimeError as exc:
                raise HTTPException(503, str(exc)) from exc
    finally:
        tmp.unlink(missing_ok=True)
    if "kill_chain_replay" in lower and REPLAY_NOTE not in (body.get("notes") or []):
        body.setdefault("notes", []).append(REPLAY_NOTE)
    body["model"] = NETFLOW_V3_HOST
    return body


@router.post("/api/forecast", response_model=ForecastResponse)
async def post_forecast(file: UploadFile = File(...), horizon_k: int = Query(3, ge=1, le=10),
                        window_s: int = Query(60, ge=1)):
    name = (file.filename or "").lower()
    if name.endswith((".pcap", ".pcapng")):
        raise HTTPException(501, "PCAP upload is not enabled yet. Upload a flow CSV (CIC-IDS style) or a windowed CSV.")
    if not name.endswith(".csv"):
        raise HTTPException(400, "Upload a .csv file.")
    frame = _read_csv(await file.read())
    present_features = [name for name in FEATURES if name in frame.columns]
    if present_features and len(present_features) != len(FEATURES):
        missing = [name for name in FEATURES if name not in frame.columns]
        raise HTTPException(422, "Missing required columns: " + ", ".join(missing) + ".")
    lowered = {column.strip().lower() for column in frame.columns}
    if "label" in lowered and "timestamp" in lowered and not all(feature in frame.columns for feature in FEATURES):
        raise HTTPException(
            400,
            "This is a CICFlowMeter CSV. POST it to /api/forecast/cicids so the CIC baseline and LSTM are used.",
        )
    if all(feature in frame.columns for feature in FEATURES):
        features, times = frame[FEATURES], (list(pd.to_datetime(frame["t"])) if "t" in frame else list(range(len(frame))))
    else:
        features, times = flows_to_windows(frame, window_s)
    if len(features) < 3:
        raise HTTPException(422, "Need at least 3 time windows of traffic to forecast.")
    try:
        return fc.forecast(features, times, K=horizon_k, mode=SYNTHETIC)
    except RuntimeError as exc:
        raise HTTPException(503, str(exc)) from exc
