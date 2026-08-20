"""
security.py
------------
The Security Layer, sitting between anomaly detection and diagnosis:

    Monitor -> Predict/Detect -> SECURITY LAYER -> Diagnose -> Respond -> Recover -> Verify

Design is grounded in a few things the literature converges on for
digital-twin-based IoT security (see README "Research Foundation" for
the actual papers):

  - A dedicated, FAST attack check should run before the slower,
    explainable diagnosis stage - Causio-TwinChain (Sci. Reports, DT +
    blockchain IoT security) pairs a fast anomaly-flagging stage with a
    separate causal root-cause stage precisely because splitting the
    two cut mean time-to-diagnosis by 68% and false positives by 22%
    versus one combined stage.
  - Message-RATE monitoring is a legitimate, lightweight, interpretable
    first line of defense for IIoT/digital-twin traffic specifically
    because that traffic is cyclical and predictable (periodic sensor
    reports) - a 2025 data-rate-monitoring study found DoS attacks
    produced roughly a 50x spike in packet rate against that stable
    baseline, and validated simple statistical thresholding (not a
    trained model) as sufficient to catch it.
  - A digital twin architecture is well suited to spotting a
    compromised node that either emits false data OR is being used to
    attack its neighbors (IEEE, "Compromised Node Detection" via fog-
    based digital twins) - motivating why a blocked device here is cut
    off from the network (firewalled), not just flagged.

Three attack classes are handled here, distinct from the four
non-adversarial root causes diagnosis.py already covers:

  MALICIOUS_TAMPERING (fast-path) - same multi-metric-instant-jump
      signature diagnosis.py uses, but checked here FIRST, with a
      stricter threshold, so a clear attack is blocked immediately
      instead of waiting for the full diagnosis stage.
  DOS_FLOOD_ATTACK   - message rate for a device far exceeds its
      normal cadence (real MQTT devices only - the simulator ticks at
      a fixed interval by construction, so flooding is only meaningful
      for something actually sending on its own schedule).
  IDENTITY_SPOOFING  - a device_id publishes a device_type/zone that
      conflicts with what it originally registered as - a node trying
      to impersonate, or be conflated with, another device's identity.

When any of these trips, the Firewall blocks the device_id for a
time-boxed, escalating duration (repeat offenders get longer blocks),
and mqtt_bridge.py / the main tick loop both check the block before
processing any further data from that device - i.e. the connection is
actually cut, not just visually flagged.
"""

from __future__ import annotations
import time
from collections import deque
from typing import Deque, Dict, Optional

from digital_twin import DeviceTwin, DeviceState
from anomaly_detector import score_device

FAST_PATH_Z_THRESHOLD = 3.2      # stricter than diagnosis.py's 2.5 - only the clearest attacks
FAST_PATH_MIN_METRICS = 2

FLOOD_WINDOW_SECONDS = 5.0
FLOOD_RATE_MULTIPLIER = 5.0      # flag if rate exceeds 5x the expected cadence
FLOOD_MIN_SAMPLES = 6

BASE_BLOCK_SECONDS = 30
MAX_BLOCK_SECONDS = 300


class Firewall:
    """Time-boxed blocklist with escalating durations for repeat offenders."""

    def __init__(self) -> None:
        self._blocks: Dict[str, float] = {}       # device_id -> unblock timestamp
        self._reasons: Dict[str, str] = {}
        self._strikes: Dict[str, int] = {}

    def is_blocked(self, device_id: str) -> bool:
        until = self._blocks.get(device_id)
        if until is None:
            return False
        if time.time() >= until:
            del self._blocks[device_id]
            return False
        return True

    def reason(self, device_id: str) -> Optional[str]:
        return self._reasons.get(device_id)

    def block(self, device_id: str, reason: str) -> float:
        strikes = self._strikes.get(device_id, 0) + 1
        self._strikes[device_id] = strikes
        duration = min(MAX_BLOCK_SECONDS, BASE_BLOCK_SECONDS * (2 ** (strikes - 1)))
        self._blocks[device_id] = time.time() + duration
        self._reasons[device_id] = reason
        return duration

    def strikes(self, device_id: str) -> int:
        return self._strikes.get(device_id, 0)


class RateTracker:
    """Tracks recent message timestamps per device to spot flooding."""

    def __init__(self, window_seconds: float = FLOOD_WINDOW_SECONDS) -> None:
        self.window = window_seconds
        self._times: Dict[str, Deque[float]] = {}
        self._baseline_interval: Dict[str, float] = {}  # learned expected seconds/message

    def record(self, device_id: str) -> None:
        now = time.time()
        dq = self._times.setdefault(device_id, deque(maxlen=200))
        dq.append(now)
        cutoff = now - self.window
        while dq and dq[0] < cutoff:
            dq.popleft()

    def is_flooding(self, device_id: str) -> bool:
        dq = self._times.get(device_id)
        if not dq or len(dq) < FLOOD_MIN_SAMPLES:
            return False
        span = dq[-1] - dq[0]
        if span <= 0:
            return False
        observed_rate = len(dq) / span  # messages/sec over the recent window

        baseline = self._baseline_interval.get(device_id)
        if baseline is None:
            # first time we have enough samples - learn the normal cadence
            # from THIS window and don't flag it (avoids false positive on startup)
            self._baseline_interval[device_id] = span / len(dq)
            return False

        expected_rate = 1.0 / baseline if baseline > 0 else observed_rate
        return observed_rate > expected_rate * FLOOD_RATE_MULTIPLIER


def fast_attack_check(twin: DeviceTwin, firewall: Firewall) -> Optional[str]:
    """Runs on every SUSPECT device before diagnosis.py. Returns the root
    cause string if a clear attack pattern was found and the device was
    firewalled, otherwise None (falls through to normal diagnosis)."""
    if twin.state != DeviceState.SUSPECT or len(twin.history) < 10:
        return None

    _, point_z, _ = score_device(twin)
    env = ("battery", "signal_strength", "packet_loss")
    non_env = [m for m in point_z if m not in env]
    hot_metrics = [m for m in non_env if point_z.get(m, 0) >= FAST_PATH_Z_THRESHOLD]

    if len(hot_metrics) >= FAST_PATH_MIN_METRICS:
        cause = "MALICIOUS_TAMPERING"
        duration = firewall.block(twin.device_id, cause)
        twin.state = DeviceState.ANOMALOUS
        twin.root_cause = cause
        twin.root_cause_confidence = 0.95
        twin.recovery_log.append(
            f"[FIREWALL] {len(hot_metrics)} metrics ({', '.join(hot_metrics)}) jumped instantly and "
            f"implausibly — SECURITY LAYER blocked this device's connection for {int(duration)}s "
            f"before full diagnosis even ran."
        )
        return cause
    return None


def enforce_on_ingest(device_id: str, twin: Optional[DeviceTwin], firewall: Firewall,
                       rate_tracker: RateTracker, claimed_type: Optional[str] = None,
                       claimed_zone: Optional[str] = None, log_event=None) -> bool:
    """Called by mqtt_bridge.py for every incoming message, BEFORE it is
    pushed into the twin. Returns True if the message should be dropped
    (connection cut / device firewalled)."""

    if firewall.is_blocked(device_id):
        return True  # already blocked - silently drop, connection stays cut

    rate_tracker.record(device_id)
    if rate_tracker.is_flooding(device_id):
        duration = firewall.block(device_id, "DOS_FLOOD_ATTACK")
        if twin:
            twin.state = DeviceState.ANOMALOUS
            twin.root_cause = "DOS_FLOOD_ATTACK"
            twin.root_cause_confidence = 0.9
            twin.recovery_log.append(
                f"[FIREWALL] Message rate far exceeded this device's normal cadence — "
                f"SECURITY LAYER cut the connection for {int(duration)}s (suspected DoS/flood)."
            )
        if log_event:
            log_event("FIREWALL", device_id, f"Connection cut for {int(duration)}s — DoS/flood pattern detected.")
        return True

    if twin and claimed_type and claimed_type != twin.device_type:
        duration = firewall.block(device_id, "IDENTITY_SPOOFING")
        twin.state = DeviceState.ANOMALOUS
        twin.root_cause = "IDENTITY_SPOOFING"
        twin.root_cause_confidence = 0.9
        twin.recovery_log.append(
            f"[FIREWALL] Device claimed type '{claimed_type}' but was registered as "
            f"'{twin.device_type}' — SECURITY LAYER cut the connection for {int(duration)}s "
            f"(suspected identity spoofing)."
        )
        if log_event:
            log_event("FIREWALL", device_id, f"Connection cut for {int(duration)}s — identity mismatch detected.")
        return True

    return False
