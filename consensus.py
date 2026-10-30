"""
consensus.py
------------
Zone consensus: the twin's estimate of what the PHYSICAL environment in a
zone actually is, from every co-located device that measures the same
quantity (a temp sensor's "temperature", a humidity sensor's
"temperature_ambient" and the standby devices all see the same room).

For each device we compute a leave-one-out, trust-weighted median of its
peers. The device's residual against that consensus is what separates:

  - a genuine environment change   (everyone moves together; residual ~0)
  - a sensor fault / drift / attack (one device moves alone; residual grows)

which a per-device baseline cannot do on its own - a frozen baseline
flags a real heatwave as "drift" on every sensor in the room.

Devices that are suspected, contained, isolated, distrusted or stale are
excluded as contributors so a faulty or lying device cannot drag the
consensus it is being judged against.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple

import clock
from config import PipelineConfig
from digital_twin import DigitalTwinRegistry, DeviceState, DeviceTwin, QUANTITY_OF

CONTRIBUTOR_STATES = (DeviceState.NORMAL, DeviceState.RECOVERED)
STALE_SECONDS = 4.0
MIN_PEERS = 2


def _group(twin: DeviceTwin) -> str:
    """Physical peer group: a real sensor's room is not the simulated room that shares its zone name."""
    return f"{twin.zone}#real" if twin.is_real else twin.zone


def weighted_median(pairs: List[Tuple[float, float]]) -> float:
    pairs = sorted(pairs)
    total = sum(w for _, w in pairs)
    acc = 0.0
    for v, w in pairs:
        acc += w
        if acc >= total / 2:
            return v
    return pairs[-1][0]


class ZoneConsensus:
    def __init__(self) -> None:
        self.zone_values: Dict[str, Dict[str, float]] = {}       # zone -> quantity -> consensus
        self.zone_baseline: Dict[str, Dict[str, Tuple[float, float]]] = {}
        self._warm: Dict[str, Dict[str, List[float]]] = {}

    def update(self, registry: DigitalTwinRegistry, tick_start: float, cfg: PipelineConfig) -> None:
        now = clock.now()
        contrib: Dict[str, Dict[str, List[Tuple[str, float, float]]]] = {}
        for twin in registry.all():
            latest = twin.latest()
            if (latest is None or twin.state not in CONTRIBUTOR_STATES or not twin.data_trusted
                    or twin.last_seen is None or now - twin.last_seen > STALE_SECONDS):
                continue
            w = max(0.05, twin.trust_score) if cfg.trust_weighted_consensus else 1.0
            for metric, value in latest.values.items():
                q = QUANTITY_OF.get(metric)
                if q:
                    contrib.setdefault(_group(twin), {}).setdefault(q, []).append((twin.device_id, value, w))

        self.zone_values = {}
        for group, per_q in contrib.items():
            if group.endswith("#real"):
                continue   # real-hardware groups feed residuals only; zone_values describe the simulated rooms
            zone = group
            for q, entries in per_q.items():
                if len(entries) >= MIN_PEERS + 1:
                    c = weighted_median([(v, w) for _, v, w in entries])
                    self.zone_values.setdefault(zone, {})[q] = c
                    self._track_zone_baseline(zone, q, c)

        for twin in registry.all():
            if twin.last_seen is None or twin.last_seen < tick_start:
                continue  # no fresh reading this tick
            latest = twin.latest()
            res: Dict[str, float] = {}
            seen: Dict[str, float] = {}
            for metric, value in latest.values.items():
                q = QUANTITY_OF.get(metric)
                if not q:
                    continue
                peers = [(v, w) for d, v, w in contrib.get(_group(twin), {}).get(q, []) if d != twin.device_id]
                if len(peers) >= MIN_PEERS:
                    c = weighted_median(peers)
                    res[metric] = value - c
                    seen[metric] = c
                    seen[f"v:{metric}"] = value   # stored together so device and consensus stay aligned
            if res:
                twin.residuals.append(res)
                twin.consensus_seen.append(seen)

    def _track_zone_baseline(self, zone: str, q: str, value: float) -> None:
        if q in self.zone_baseline.get(zone, {}):
            return
        warm = self._warm.setdefault(zone, {}).setdefault(q, [])
        warm.append(value)
        if len(warm) >= 15:
            mean = sum(warm) / len(warm)
            sd = max((sum((x - mean) ** 2 for x in warm) / len(warm)) ** 0.5, 0.3)
            self.zone_baseline.setdefault(zone, {})[q] = (mean, sd)

    def zone_shift(self, zone: str) -> Dict[str, float]:
        """How far each zone quantity has moved from the zone's own early baseline (in its units)."""
        out: Dict[str, float] = {}
        for q, c in self.zone_values.get(zone, {}).items():
            base = self.zone_baseline.get(zone, {}).get(q)
            if base:
                out[q] = c - base[0]
        return out

    def reset_zone_baseline(self, zone: str) -> None:
        self.zone_baseline.pop(zone, None)
        self._warm.pop(zone, None)


def device_has_peers(twin: DeviceTwin) -> bool:
    return bool(twin.residuals)


def zone_value(cons: ZoneConsensus, zone: str, q: str) -> Optional[float]:
    return cons.zone_values.get(zone, {}).get(q)
