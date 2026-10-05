"""Kill-chain stages, MITRE ATT&CK mapping and defensive actions.
Member 1 must use STAGES (same order) when writing stage labels."""

STAGES = ["benign", "reconnaissance", "initial_access", "lateral_movement",
          "command_and_control", "exfiltration"]

MITRE = {
    "reconnaissance":      {"tactic": "Reconnaissance",      "id": "TA0043"},
    "initial_access":      {"tactic": "Initial Access",      "id": "TA0001"},
    "lateral_movement":    {"tactic": "Lateral Movement",    "id": "TA0008"},
    "command_and_control": {"tactic": "Command and Control", "id": "TA0011"},
    "exfiltration":        {"tactic": "Exfiltration",        "id": "TA0010"},
}

ACTIONS = {
    "reconnaissance":      "Rate-limit and log scanning sources; review exposed ports.",
    "initial_access":      "Block the source, enforce MFA on exposed services, patch public-facing hosts.",
    "lateral_movement":    "Segment the affected subnet and restrict SMB/RDP between workstations.",
    "command_and_control": "Block outbound beaconing destinations and isolate the suspected host.",
    "exfiltration":        "Cut egress from the data host and preserve logs for forensics.",
}

def describe(stage: str) -> dict:
    m = MITRE.get(stage, {"tactic": "Benign", "id": None})
    return {"stage": stage, "tactic": m["tactic"], "mitre_id": m["id"], "action": ACTIONS.get(stage)}
