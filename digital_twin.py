"""
digital_twin.py
----------------
Maintains an in-memory Digital Twin for every IoT device.

A "Digital Twin" here is a live, continuously-updated software mirror of a
device: its last known readings, health state, trust, history buffers (raw
values, and residuals against its zone's consensus), transport provenance
(sequence numbers, publisher fingerprint, message authentication), the
evidence and cause probabilities behind its latest diagnosis, and its
lifecycle state (NORMAL / SUSPECT / ANOMALOUS / ISOLATED / RECOVERING /
RECOVERED).

Every other module reads and writes through this single source of truth,
so the dashboard and the experiment harness always see the same state.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import deque
from enum import Enum
from typing import Deque, Dict, List, Optional

import clock

# Which physical quantity each metric measures. Metrics that map to the
# same quantity on co-located devices form a zone's redundancy group, which
# is what lets the twin tell "this sensor is wrong" from "the room changed".
QUANTITY_OF = {
    "temperature": "T", "temperature_ambient": "T",
    "humidity": "H", "humidity_ambient": "H",
}
ENV_METRICS = ("battery", "signal_strength", "packet_loss")


class DeviceState(str, Enum):
    NORMAL = "NORMAL"
    SUSPECT = "SUSPECT"          # anomaly detector flagged, not yet diagnosed
    ANOMALOUS = "ANOMALOUS"      # diagnosis confirmed a real problem
    CONTAINED = "CONTAINED"      # online but its data is distrusted while evidence accumulates
    ISOLATED = "ISOLATED"        # cut off from the pipeline
    RECOVERING = "RECOVERING"    # recovery action executed, verification running
    RECOVERED = "RECOVERED"      # verified healthy again


@dataclass
class Reading:
    timestamp: float
    values: Dict[str, float]


@dataclass
class DeviceTwin:
    device_id: str
    device_type: str
    zone: str
    is_backup: bool = False
    backup_for: Optional[str] = None
    gateway_id: Optional[str] = None   # the zone gateway this device's traffic flows through

    state: DeviceState = DeviceState.NORMAL
    trust_score: float = 1.0
    trust_state: Dict[str, float] = field(default_factory=dict)   # model-specific (e.g. beta alpha/beta)
    history: Deque[Reading] = field(default_factory=lambda: deque(maxlen=60))
    residuals: Deque[Dict[str, float]] = field(default_factory=lambda: deque(maxlen=60))
    consensus_seen: Deque[Dict[str, float]] = field(default_factory=lambda: deque(maxlen=60))
    last_anomaly_score: float = 0.0
    last_point_z: Dict[str, float] = field(default_factory=dict)
    last_baseline_z: Dict[str, float] = field(default_factory=dict)
    last_residual_z: Dict[str, float] = field(default_factory=dict)
    root_cause: Optional[str] = None
    root_cause_confidence: float = 0.0
    posterior: Dict[str, float] = field(default_factory=dict)
    evidence: Dict[str, float] = field(default_factory=dict)
    explanation: List[str] = field(default_factory=list)
    active_since: float = field(default_factory=clock.now)
    recovery_log: List[str] = field(default_factory=list)
    rerouted_to: Optional[str] = None
    is_real: bool = False   # fed by real hardware over MQTT rather than the simulator
    firewall_blocked: bool = False
    firewall_reason: Optional[str] = None
    data_trusted: bool = True   # False = online but excluded from consensus/consumers

    # transport provenance
    last_seen: Optional[float] = None
    last_seq: Optional[int] = None
    publisher_id: Optional[str] = None
    provenance_events: Deque[float] = field(default_factory=lambda: deque(maxlen=50))
    auth_failures: Deque[float] = field(default_factory=lambda: deque(maxlen=50))
    messages_dropped: int = 0

    # Frozen calibration snapshot, captured once the device has enough clean
    # history, and cleared/re-captured after any recalibration/recovery.
    # Keys: "<metric>" raw mean/std (std floored), "n:<metric>" raw noise
    # (unfloored), "r:<metric>" mean/std of the residual against the zone
    # consensus (i.e. this device's own legitimate calibration offset).
    baseline_mean: Dict[str, float] = field(default_factory=dict)
    baseline_std: Dict[str, float] = field(default_factory=dict)
    # The device's last VERIFIED-good offset against its zone (metric -> (mean, sd)).
    # Unlike the baseline above it survives re-learning, so an attacker's
    # offset cannot be laundered into "normal" by a recalibration.
    ref_offset: Dict[str, tuple] = field(default_factory=dict)

    # recovery bookkeeping
    suspect_since: Optional[float] = None
    contained_ticks: int = 0
    repair_eta: Optional[float] = None
    failed_actions: List[str] = field(default_factory=list)
    incident_id: Optional[int] = None
    current_action: Optional[str] = None
    verify_counter: int = 0
    verify_needed: int = 0
    verify_failures: int = 0
    escalation_level: int = 0

    def push_reading(self, values: Dict[str, float], ts: Optional[float] = None) -> None:
        ts = clock.now() if ts is None else ts
        self.history.append(Reading(timestamp=ts, values=values))
        self.last_seen = ts

    def latest(self) -> Optional[Reading]:
        return self.history[-1] if self.history else None

    def quantities(self) -> Dict[str, str]:
        """metric -> quantity for every metric this device reports that has a zone peer group."""
        latest = self.latest()
        if not latest:
            return {}
        return {m: QUANTITY_OF[m] for m in latest.values if m in QUANTITY_OF}

    def reset_learning(self) -> None:
        self.history.clear()
        self.residuals.clear()
        self.consensus_seen.clear()
        self.baseline_mean.clear()
        self.baseline_std.clear()

    def spark(self, n: int = 40) -> dict:
        """Recent primary reading next to the zone consensus it was judged against (for the dashboard)."""
        latest = self.latest()
        if not latest:
            return {}
        quantity = [m for m in latest.values if m in QUANTITY_OF]
        if quantity and self.consensus_seen:
            m = quantity[0]
            pts = [(c.get(f"v:{m}"), c.get(m)) for c in list(self.consensus_seen)[-n:]]
            return {"metric": m, "v": [p[0] for p in pts], "c": [p[1] for p in pts]}
        sensed = [m for m in latest.values if m not in ENV_METRICS]
        if not sensed:
            return {}
        m = sensed[0]
        return {"metric": m, "v": [r.values.get(m) for r in list(self.history)[-n:]], "c": []}

    def as_dict(self) -> dict:
        latest = self.latest()
        return {
            "spark": self.spark(),
            "suspect_since": self.suspect_since,
            "incident_id": self.incident_id,
            "device_id": self.device_id,
            "device_type": self.device_type,
            "zone": self.zone,
            "is_backup": self.is_backup,
            "backup_for": self.backup_for,
            "gateway_id": self.gateway_id,
            "is_real": self.is_real,
            "firewall_blocked": self.firewall_blocked,
            "firewall_reason": self.firewall_reason,
            "data_trusted": self.data_trusted,
            "state": self.state.value,
            "trust_score": round(self.trust_score, 3),
            "last_values": latest.values if latest else {},
            "last_anomaly_score": round(self.last_anomaly_score, 3),
            "residual_z": self.last_residual_z,
            "root_cause": self.root_cause,
            "root_cause_confidence": round(self.root_cause_confidence, 3),
            "posterior": {k: round(v, 3) for k, v in sorted(self.posterior.items(), key=lambda kv: -kv[1])[:4]},
            "evidence": {k: round(v, 3) for k, v in self.evidence.items()},
            "explanation": self.explanation[-6:],
            "current_action": self.current_action,
            "rerouted_to": self.rerouted_to,
            "recovery_log": self.recovery_log[-5:],
        }


class DigitalTwinRegistry:
    """Holds every DeviceTwin in the network."""

    def __init__(self) -> None:
        self.devices: Dict[str, DeviceTwin] = {}

    def register(self, twin: DeviceTwin) -> None:
        self.devices[twin.device_id] = twin

    def get(self, device_id: str) -> Optional[DeviceTwin]:
        return self.devices.get(device_id)

    def all(self) -> List[DeviceTwin]:
        return list(self.devices.values())

    def in_zone(self, zone: str) -> List[DeviceTwin]:
        return [d for d in self.devices.values() if d.zone == zone]

    def snapshot(self) -> List[dict]:
        return [d.as_dict() for d in self.devices.values()]

    def find_backup_for(self, device_id: str) -> Optional[DeviceTwin]:
        twin = self.get(device_id)
        if not twin:
            return None
        for candidate in self.devices.values():
            if (
                candidate.is_backup
                and candidate.device_type == twin.device_type
                and candidate.zone == twin.zone
                and candidate.state in (DeviceState.NORMAL, DeviceState.RECOVERED)
                and candidate.device_id != device_id
                and candidate.backup_for in (None, device_id)
            ):
                return candidate
        return None

    def find_failover_gateway(self, gateway_id: str) -> Optional[DeviceTwin]:
        gw = self.get(gateway_id)
        if not gw:
            return None
        for candidate in self.devices.values():
            if (
                candidate.device_type == "gateway"
                and candidate.device_id != gateway_id
                and candidate.state in (DeviceState.NORMAL, DeviceState.RECOVERED)
            ):
                return candidate
        return None
