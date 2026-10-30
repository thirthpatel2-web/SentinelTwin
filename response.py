"""
response.py
-----------
Choosing WHAT to do when the diagnosis is uncertain.

Diagnosis gives a probability per cause, not a certainty. Acting on the
single most likely cause is dangerous exactly where it matters most:
"recalibrate" is the right fix for a drifting sensor, but applied to a
device that is actually being tampered with, it absorbs the attacker's
offset into the calibration. "Quarantine" is right for an attack, but on
a merely faulty device it costs availability for nothing.

So the default policy picks the action with the lowest EXPECTED cost over
the cause probabilities:

    action* = argmin_a  sum_c  P(c | evidence) * COST[a][c]  + availability penalties

The cost table is explicit and readable (and is itself something the
evaluation varies). It produces a behaviour no argmax policy can: under
genuine drift-vs-attack ambiguity it chooses DISTRUST_DATA - keep the
device online, stop trusting its data, cover the service with a standby,
and keep gathering evidence until the picture sharpens.

Policies (for the evaluation):
    expected_cost   the SentinelTwin policy described above
    argmax          act on the most likely cause only (the original design)
    naive_restart   isolate/restart on any anomaly (common industrial baseline)
    no_heal         detect and report only
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from config import PipelineConfig
from digital_twin import DeviceTwin, DigitalTwinRegistry

ACTIONS = ["OBSERVE", "RECALIBRATE", "ACTIVATE_BACKUP", "REROUTE", "GATEWAY_FAILOVER",
           "QUARANTINE", "DISTRUST_DATA"]

# COST[action][cause] on a 0-10 scale: harm to data integrity + availability
# + operator effort if this action is taken and that cause is the truth.
C = ["HARDWARE_FAULT", "NETWORK_FAILURE", "UPSTREAM_FAILURE", "GATEWAY_FAILURE", "SENSOR_DRIFT",
     "MALICIOUS_TAMPERING", "STEALTHY_TAMPERING", "DOS_FLOOD_ATTACK", "IDENTITY_SPOOFING", "UNCLASSIFIED_ANOMALY"]
_TABLE = {
    #                  HW   NET  UPS  GW   DRIFT TAMP STLTH DOS  SPOOF UNCL
    "OBSERVE":        [6,   5,   0.5, 7,   4,    9,   7,    8,   8,    2],
    "RECALIBRATE":    [6,   6,   5,   7,   0.5,  9,   8,    8,   8,    4],
    "ACTIVATE_BACKUP":[1,   3,   4,   5,   2.5,  4,   4,    5,   5,    3],
    "REROUTE":        [5,   1,   3,   5,   4,    7,   6,    5,   6,    3],
    "GATEWAY_FAILOVER":[6,  5,   3,   1,   6,    7,   7,    6,   7,    5],
    "QUARANTINE":     [4,   5,   6,   6,   5,    1,   1.5,  1,   1,    4],
    "DISTRUST_DATA":  [2.5, 4,   4,   5,   2,    3,   2,    5,   5,    2],
}
COST: Dict[str, Dict[str, float]] = {a: dict(zip(C, row)) for a, row in _TABLE.items()}

ACTION_FOR_CAUSE = {
    "HARDWARE_FAULT": "ACTIVATE_BACKUP", "NETWORK_FAILURE": "REROUTE", "UPSTREAM_FAILURE": "OBSERVE",
    "GATEWAY_FAILURE": "GATEWAY_FAILOVER", "SENSOR_DRIFT": "RECALIBRATE",
    "MALICIOUS_TAMPERING": "QUARANTINE", "STEALTHY_TAMPERING": "QUARANTINE",
    "DOS_FLOOD_ATTACK": "QUARANTINE", "IDENTITY_SPOOFING": "QUARANTINE",
    "UNCLASSIFIED_ANOMALY": "ACTIVATE_BACKUP",
}

FAILED_ACTION_PENALTY = 6.0
NO_STANDBY_PENALTY = 4.0


def _availability_penalties(twin: DeviceTwin, registry: DigitalTwinRegistry) -> Dict[str, Tuple[float, str]]:
    """Pre-action safety check against the twin: what would each action do to service coverage?"""
    pen: Dict[str, Tuple[float, str]] = {}
    is_gw = twin.device_type == "gateway"
    has_backup = registry.find_backup_for(twin.device_id) is not None
    if is_gw:
        if registry.find_failover_gateway(twin.device_id) is None:
            pen["GATEWAY_FAILOVER"] = (NO_STANDBY_PENALTY, "no healthy gateway to fail over to")
        for a in ("ACTIVATE_BACKUP", "REROUTE", "RECALIBRATE"):
            pen[a] = (NO_STANDBY_PENALTY, "not applicable to a gateway")
    else:
        pen["GATEWAY_FAILOVER"] = (float("inf"), "only gateways can fail over")
        if not has_backup:
            for a in ("ACTIVATE_BACKUP", "REROUTE", "DISTRUST_DATA"):
                pen[a] = (NO_STANDBY_PENALTY, "no standby device in the zone - service would be lost")
    return pen


def expected_costs(twin: DeviceTwin, registry: DigitalTwinRegistry,
                   exclude: Optional[List[str]] = None) -> Dict[str, float]:
    post = twin.posterior or {twin.root_cause or "UNCLASSIFIED_ANOMALY": 1.0}
    pen = _availability_penalties(twin, registry)
    out = {}
    for a in ACTIONS:
        cost = sum(p * COST[a].get(c, 5.0) for c, p in post.items())
        cost += pen.get(a, (0.0, ""))[0]
        if exclude and a in exclude:
            cost += FAILED_ACTION_PENALTY
        out[a] = round(cost, 3)
    return out


def choose_action(twin: DeviceTwin, registry: DigitalTwinRegistry, cfg: PipelineConfig,
                  exclude: Optional[List[str]] = None) -> Tuple[str, Dict[str, float], str]:
    costs = expected_costs(twin, registry, exclude)
    cause = twin.root_cause or "UNCLASSIFIED_ANOMALY"
    if cfg.policy == "no_heal":
        return "OBSERVE", costs, "policy: detect and report only"
    if cfg.policy == "naive_restart":
        return "ACTIVATE_BACKUP", costs, "policy: restart/isolate on any anomaly"
    if cfg.policy == "argmax":
        action = ACTION_FOR_CAUSE.get(cause, "ACTIVATE_BACKUP")
        if twin.device_type == "gateway" and action in ("ACTIVATE_BACKUP", "REROUTE", "RECALIBRATE"):
            action = "GATEWAY_FAILOVER"
        if exclude and action in exclude:
            action = "QUARANTINE" if action != "QUARANTINE" else "ACTIVATE_BACKUP"
        return action, costs, f"policy: fixed action for most likely cause {cause}"
    action = min(costs, key=costs.get)
    ranked = sorted(costs.items(), key=lambda kv: kv[1])[:3]
    reason = "lowest expected cost: " + ", ".join(f"{a}={c:.2f}" for a, c in ranked)
    return action, costs, reason
