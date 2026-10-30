"""
incidents.py
------------
One record per incident, with an explicit timestamp for every phase of
the closed loop, so recovery is measured rather than asserted:

    onset (ground truth, simulator only)
    t_detect    the device first turned SUSPECT (or was caught at ingestion)
    t_diagnose  a root cause was confirmed
    t_contain   the first response action was executed
    t_verified  post-action verification passed (device RECOVERED)

Derived metrics (see experiments/metrics.py):
    MTTD          t_detect   - onset
    time-to-diagnose t_diagnose - t_detect
    time-to-contain  t_contain  - t_detect
    MTTR          t_verified - t_detect
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional


@dataclass
class Incident:
    id: int
    device_id: str
    zone: str
    device_type: str
    is_real: bool
    t_detect: float
    t_diagnose: float
    cause: str
    confidence: float
    posterior: Dict[str, float]
    explanation: List[str]
    evidence: Dict[str, float]
    gt_mode: str = "NONE"
    gt_expected: str = "NONE"
    gt_onset: Optional[float] = None
    gt_attack: bool = False
    actions: List[dict] = field(default_factory=list)
    t_contain: Optional[float] = None
    t_verified: Optional[float] = None
    verify_failures: int = 0
    escalations: int = 0
    outcome: str = "OPEN"          # OPEN | RECOVERED | MANUAL | UNVERIFIED_CLOSE
    gt_active_at_close: Optional[bool] = None

    def as_dict(self) -> dict:
        return asdict(self)


class IncidentLog:
    def __init__(self) -> None:
        self._items: Dict[int, Incident] = {}
        self._next = 1

    def open(self, **kw) -> Incident:
        inc = Incident(id=self._next, **kw)
        self._items[inc.id] = inc
        self._next += 1
        return inc

    def get(self, incident_id: Optional[int]) -> Optional[Incident]:
        return self._items.get(incident_id) if incident_id is not None else None

    def all(self) -> List[Incident]:
        return list(self._items.values())

    def recent(self, n: int = 20) -> List[dict]:
        return [i.as_dict() for i in list(self._items.values())[-n:]]
