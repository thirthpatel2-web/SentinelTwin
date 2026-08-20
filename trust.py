"""
trust.py
--------
Maintains a rolling trust_score (0..1) per device using an exponential
moving average of (1 - anomaly_score) each tick, with an extra penalty
whenever a device is diagnosed MALICIOUS_TAMPERING (trust should drop
much faster from suspected tampering than from an ordinary hardware
blip) and slow recovery once a device is verified healthy again.

Trust feeds the recovery engine's decision confidence and is shown on
the dashboard so a human can see *why* the system chose to isolate a
device rather than just wait.
"""

from __future__ import annotations
from digital_twin import DeviceTwin, DeviceState

ALPHA_DECAY = 0.35          # weight given to the newest observation
MALICIOUS_PENALTY = 0.4
RECOVERY_GAIN_PER_TICK = 0.08


def update_trust(twin: DeviceTwin) -> None:
    good_signal = 1.0 - twin.last_anomaly_score

    if twin.state == DeviceState.RECOVERED:
        twin.trust_score = min(1.0, twin.trust_score + RECOVERY_GAIN_PER_TICK)
        return

    twin.trust_score = (1 - ALPHA_DECAY) * twin.trust_score + ALPHA_DECAY * good_signal

    if twin.root_cause == "MALICIOUS_TAMPERING" and twin.state == DeviceState.ANOMALOUS:
        twin.trust_score = max(0.0, twin.trust_score - MALICIOUS_PENALTY)

    twin.trust_score = round(max(0.0, min(1.0, twin.trust_score)), 3)
