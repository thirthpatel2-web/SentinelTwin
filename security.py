"""
security.py
------------
The Security Layer, sitting between anomaly detection and diagnosis:

    Monitor -> Detect -> SECURITY LAYER -> Diagnose -> Respond -> Recover -> Verify

It works on two planes:

  Transport plane (every message, in ingest.py, before data reaches a twin)
    - DOS_FLOOD_ATTACK: per-device message rate far above that device's
      own learned cadence. Two detectors are provided so the evaluation
      can compare them: a multiple-of-learned-cadence rule (default) and
      the mu+3sigma packet-rate rule of Rodrigues et al., Sensors 2025.
    - IDENTITY_SPOOFING: a message claims a device_type or zone that
      conflicts with what the device_id registered as.
    - Provenance: sequence-number regressions/jumps, a publisher
      fingerprint that differs from the registered one, and failed
      message authentication (optional per-device MAC). These do not
      block on their own; they are recorded as evidence for diagnosis.

  Data plane (every tick, on SUSPECT twins, before diagnosis.py)
    - MALICIOUS_TAMPERING fast-path: two or more sensed metrics jump
      past a strict z-score threshold in one tick. A clear attack is
      blocked immediately instead of waiting for full diagnosis.

The Firewall blocks a key for a time-boxed, escalating window
(30s -> 60s -> 120s -> 240s, capped at 300s). A key is either a whole
device_id or, when provenance shows a distinct rogue publisher, just
"device_id|publisher" - so the genuine device keeps working while the
impostor is cut off (fingerprint-scoped quarantine).
"""

from __future__ import annotations
import statistics
from collections import deque
from typing import Deque, Dict, List, Optional

import clock
from digital_twin import DeviceTwin, DeviceState, ENV_METRICS

FAST_PATH_Z_THRESHOLD = 3.2      # stricter than diagnosis' jump threshold - only the clearest attacks
FAST_PATH_MIN_METRICS = 2

FLOOD_WINDOW_SECONDS = 5.0
FLOOD_RATE_MULTIPLIER = 5.0      # flag if rate exceeds 5x the learned cadence
FLOOD_MIN_SAMPLES = 6
DEFAULT_INTERVAL_SECONDS = 1.5

SEQ_JUMP_LIMIT = 50              # gaps up to this are ordinary packet loss
PROVENANCE_WINDOW_SECONDS = 30.0

BASE_BLOCK_SECONDS = 30
MAX_BLOCK_SECONDS = 300


def publisher_key(device_id: str, publisher: Optional[str]) -> str:
    return f"{device_id}|{publisher}"


class Firewall:
    """Time-boxed blocklist with escalating durations for repeat offenders."""

    def __init__(self, permanent: bool = False) -> None:
        self.permanent = permanent      # baseline policy for the evaluation: never unblock
        self._blocks: Dict[str, float] = {}
        self._reasons: Dict[str, str] = {}
        self._strikes: Dict[str, int] = {}
        self.history: List[dict] = []

    def is_blocked(self, key: str) -> bool:
        until = self._blocks.get(key)
        if until is None:
            return False
        if clock.now() >= until:
            del self._blocks[key]
            return False
        return True

    def reason(self, key: str) -> Optional[str]:
        return self._reasons.get(key)

    def block(self, key: str, reason: str) -> float:
        strikes = self._strikes.get(key, 0) + 1
        self._strikes[key] = strikes
        duration = float("inf") if self.permanent else min(
            MAX_BLOCK_SECONDS, BASE_BLOCK_SECONDS * (2 ** (strikes - 1)))
        self._blocks[key] = clock.now() + duration
        self._reasons[key] = reason
        self.history.append({"ts": clock.now(), "key": key, "reason": reason, "duration": duration})
        return duration

    def unblock(self, key: str) -> None:
        self._blocks.pop(key, None)

    def strikes(self, key: str) -> int:
        return self._strikes.get(key, 0)


class RateTracker:
    """Per-device message-rate monitor learning each device's own cadence."""

    def __init__(self, window_seconds: float = FLOOD_WINDOW_SECONDS, mode: str = "multiple") -> None:
        self.window = window_seconds
        self.mode = mode                                 # "multiple" | "mu3sigma"
        self._times: Dict[str, Deque[float]] = {}
        self._interval: Dict[str, float] = {}            # learned seconds/message (EMA)
        self._counts: Dict[str, Deque[int]] = {}         # window counts, for mu+3sigma

    def record(self, device_id: str, ts: float) -> bool:
        """Record an arrival; returns True if the device is currently flooding."""
        dq = self._times.setdefault(device_id, deque(maxlen=400))
        prev = dq[-1] if dq else None
        dq.append(ts)
        cutoff = ts - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()
        flooding = self._flooding(device_id, len(dq))
        if not flooding:
            # only learn the cadence from traffic that is not itself a flood
            if prev is not None and ts > prev:
                iat = ts - prev
                old = self._interval.get(device_id, DEFAULT_INTERVAL_SECONDS)
                if iat >= 0.5 * old:   # a burst must not teach the tracker that bursts are normal
                    self._interval[device_id] = 0.9 * old + 0.1 * iat
            self._counts.setdefault(device_id, deque(maxlen=200)).append(len(dq))
        return flooding

    def _flooding(self, device_id: str, n: int) -> bool:
        if n < FLOOD_MIN_SAMPLES:
            return False
        if self.mode == "mu3sigma":
            hist = self._counts.get(device_id)
            if not hist or len(hist) < 10:
                return False
            mu = statistics.fmean(hist)
            sd = max(statistics.pstdev(hist), 0.5)
            return n > mu + 3 * sd
        expected = self.window / self._interval.get(device_id, DEFAULT_INTERVAL_SECONDS)
        return n > FLOOD_RATE_MULTIPLIER * max(expected, 1.0)


def note_provenance(twin: DeviceTwin, seq: Optional[int], publisher: Optional[str],
                    auth_ok: Optional[bool], ts: float) -> List[str]:
    """Updates a twin's transport-provenance record. Returns the anomalies seen in this message."""
    issues: List[str] = []
    if auth_ok is False:
        twin.auth_failures.append(ts)
        issues.append("auth_failure")
    if publisher:
        if twin.publisher_id is None:
            twin.publisher_id = publisher
        elif publisher != twin.publisher_id:
            issues.append("publisher_mismatch")
    if seq is not None and twin.last_seq is not None:
        if seq <= twin.last_seq or seq - twin.last_seq > SEQ_JUMP_LIMIT:
            issues.append("seq_anomaly")
    if seq is not None and (publisher is None or publisher == twin.publisher_id):
        twin.last_seq = seq
    for _ in issues:
        twin.provenance_events.append(ts)
    return issues


def provenance_rate(twin: DeviceTwin) -> float:
    """Provenance anomalies per message over the recent window (0..1+)."""
    now = clock.now()
    recent = sum(1 for t in twin.provenance_events if now - t <= PROVENANCE_WINDOW_SECONDS)
    expected_msgs = max(1.0, PROVENANCE_WINDOW_SECONDS / DEFAULT_INTERVAL_SECONDS)
    return recent / expected_msgs


def fast_attack_check(twin: DeviceTwin, firewall: Firewall) -> Optional[str]:
    """Runs on every SUSPECT device before diagnosis. Returns the root cause
    if a clear attack pattern was found and the device was firewalled."""
    if twin.state != DeviceState.SUSPECT or len(twin.history) < 10:
        return None
    if twin.device_type == "gateway":
        return None   # throughput and CPU load co-vary physically under overload - not a tampering signature
    hot = [m for m, z in twin.last_point_z.items() if m not in ENV_METRICS and z >= FAST_PATH_Z_THRESHOLD]
    if len(hot) < FAST_PATH_MIN_METRICS:
        return None
    cause = "MALICIOUS_TAMPERING"
    duration = firewall.block(twin.device_id, cause)
    twin.state = DeviceState.ANOMALOUS
    twin.root_cause = cause
    twin.root_cause_confidence = 0.95
    twin.posterior = {cause: 0.95}
    twin.firewall_blocked = True
    twin.firewall_reason = cause
    twin.explanation = [f"{len(hot)} metrics ({', '.join(hot)}) jumped instantly and implausibly in one tick"]
    twin.recovery_log.append(
        f"[FIREWALL] {len(hot)} metrics ({', '.join(hot)}) jumped instantly and implausibly - "
        f"SECURITY LAYER blocked this device for {_fmt(duration)} before full diagnosis ran."
    )
    return cause


def _fmt(duration: float) -> str:
    return "permanently" if duration == float("inf") else f"{int(duration)}s"
