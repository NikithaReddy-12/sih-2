from typing import Dict, List, Optional
from pydantic import BaseModel

class HeuristicStage(BaseModel):
    host: str
    stage: str
    tactic: str
    mitre_id: str
    score: float
    source: str
    rule_values: dict


class TimelineEntry(BaseModel):
    t: str
    observed: bool
    prob: float
    attack_prob: float
    stage: str
    tactic: str
    mitre_id: Optional[str] = None
    action: Optional[str] = None
    heuristic_stages: List[HeuristicStage] = []

class FeatureContribution(BaseModel):
    name: str
    shap: float
    value: float
    kind: Optional[str] = None
    horizon: Optional[int] = None
    timestep: Optional[int] = None
    attribution: Optional[float] = None
    share: Optional[float] = None
    group: Optional[str] = None

class FlaggedFlow(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes: Optional[float] = None
    tcp_flags: Optional[str] = None

class FlaggedWindow(BaseModel):
    t: str
    stage: str
    score: float
    top_features: List[FeatureContribution]
    flows: List[FlaggedFlow] = []
    flows_label: Optional[str] = None

class HostStepProb(BaseModel):
    t: str
    attack_prob: float


class MitreTactic(BaseModel):
    stage: str
    tactic: str
    mitre_id: str


class HostForecast(BaseModel):
    host: str
    peak_attack_prob: float
    stage: str
    mitre_tactic: str
    mitre_id: Optional[str] = None
    per_step_attack_prob: List[HostStepProb] = []
    explanation: List[FeatureContribution] = []
    explanation_source: Optional[str] = None
    heuristic_stages: List[HeuristicStage] = []
    source: Optional[str] = None
    score: Optional[float] = None
    rule_values: Optional[dict] = None
    flows_in_flagged_window: List[FlaggedFlow] = []


class ForecastResponse(BaseModel):
    model: str
    horizon_k: int
    windows: int
    overall_risk: float
    observed_attack_probability: Optional[float] = None
    timeline: List[TimelineEntry]
    explanation: List[FeatureContribution] = []
    explanation_host: Optional[str] = None
    explanation_source: Optional[str] = None
    stage_matched: Optional[int] = None
    stage_total: Optional[int] = None
    flagged_unlabelled: Optional[int] = None
    heuristic_hosts: List[HeuristicStage] = []
    heuristic_timeline: Dict[str, List[HeuristicStage]] = {}
    method: Optional[str] = None
    flagged_windows: List[FlaggedWindow]
    next_action: Optional[str] = None
    supported_stages: Optional[List[str]] = None
    not_predicted_stages: Optional[List[str]] = None
    heuristic_stage_names: Optional[List[str]] = None
    mitre: Optional[List[MitreTactic]] = None
    hosts: Optional[List[HostForecast]] = None
    current_hosts: Optional[List[HostForecast]] = None
    flag_basis: Optional[str] = None
    network_risk_definition: Optional[str] = None
    notes: Optional[List[str]] = None
