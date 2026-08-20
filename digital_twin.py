"""
digital_twin.py
----------------
Maintains an in-memory Digital Twin for every simulated IoT device.

A "Digital Twin" here is a live, continuously-updated software mirror of a
physical device: its last known readings, health status, trust score,
history buffer (for anomaly detection), and current lifecycle state
(NORMAL / SUSPECT / ANOMALOUS / ISOLATED / RECOVERING / RECOVERED).

Every other module (anomaly_detector, diagnosis, trust, recovery) reads
and writes through this single source of truth, so the dashboard always
reflects the true state of the "network".
"""

from __future__ import annotations
from dataclasses import dataclass, field
from collections import deque
from enum import Enum
from time import time
from typing import Deque, Dict, List, Optional


class DeviceState(str, Enum):
    NORMAL = "NORMAL"
    SUSPECT = "SUSPECT"          # anomaly detector flagged, not yet diagnosed
    ANOMALOUS = "ANOMALOUS"      # diagnosis confirmed a real problem
    ISOLATED = "ISOLATED"        # recovery engine has cut it off
    RECOVERING = "RECOVERING"    # recovery action in progress / verifying
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

    state: DeviceState = DeviceState.NORMAL
    trust_score: float = 1.0                  # 0..1
    history: Deque[Reading] = field(default_factory=lambda: deque(maxlen=50))
    last_anomaly_score: float = 0.0
    root_cause: Optional[str] = None
    root_cause_confidence: float = 0.0
    active_since: float = field(default_factory=time)
    recovery_log: List[str] = field(default_factory=list)
    rerouted_to: Optional[str] = None
    is_real: bool = False   # True for a device fed by mqtt_bridge.py (actual hardware), not the simulator
    firewall_blocked: bool = False
    firewall_reason: Optional[str] = None

    # Frozen calibration snapshot (mean/std per metric) captured once the
    # device has enough clean history. Used to catch SLOW drift, which a
    # rolling window can't see once the drift is baked into the window
    # itself. Cleared and re-captured after any recalibration/recovery.
    baseline_mean: Dict[str, float] = field(default_factory=dict)
    baseline_std: Dict[str, float] = field(default_factory=dict)

    def push_reading(self, values: Dict[str, float]) -> None:
        self.history.append(Reading(timestamp=time(), values=values))

    def latest(self) -> Optional[Reading]:
        return self.history[-1] if self.history else None

    def as_dict(self) -> dict:
        latest = self.latest()
        return {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "zone": self.zone,
            "is_backup": self.is_backup,
            "backup_for": self.backup_for,
            "is_real": self.is_real,
            "firewall_blocked": self.firewall_blocked,
            "firewall_reason": self.firewall_reason,
            "state": self.state.value,
            "trust_score": round(self.trust_score, 3),
            "last_values": latest.values if latest else {},
            "last_anomaly_score": round(self.last_anomaly_score, 3),
            "root_cause": self.root_cause,
            "root_cause_confidence": round(self.root_cause_confidence, 3),
            "rerouted_to": self.rerouted_to,
            "recovery_log": self.recovery_log[-5:],
        }


class DigitalTwinRegistry:
    """Holds every DeviceTwin in the simulated network."""

    def __init__(self) -> None:
        self.devices: Dict[str, DeviceTwin] = {}

    def register(self, twin: DeviceTwin) -> None:
        self.devices[twin.device_id] = twin

    def get(self, device_id: str) -> Optional[DeviceTwin]:
        return self.devices.get(device_id)

    def all(self) -> List[DeviceTwin]:
        return list(self.devices.values())

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
            ):
                return candidate
        return None
