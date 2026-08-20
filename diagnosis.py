"""
diagnosis.py
------------
Turns a SUSPECT device into an explained diagnosis: which of the four
root-cause classes is most likely, with a confidence score and a
plain-English reason (for the "explainable" requirement).

This is intentionally a transparent rule-engine, not a black-box
classifier, evaluated against the same signals a network engineer would
look at:

  NETWORK_FAILURE     signal_strength collapsing + packet_loss rising
  HARDWARE_FAULT      exactly one metric far out of range INSTANTLY
                       (high point z-score against the recent window)
                       while signal/battery stay normal
  SENSOR_DRIFT         one metric has wandered far from its original
                       calibration baseline (high baseline z-score) but
                       tick-to-tick change is small (low point z-score)
                       - the classic slow-drift signature
  MALICIOUS_TAMPERING  two or more metrics jump together, instantly, to
                       physically implausible values, while signal stays
                       suspiciously perfect (classic spoofed-data pattern)
"""

from __future__ import annotations
from typing import Optional

from digital_twin import DeviceTwin, DeviceState
from anomaly_detector import score_device

DIAGNOSIS_MIN_HISTORY = 10
POINT_Z_THRESHOLD = 2.5
BASELINE_Z_THRESHOLD = 3.0


def diagnose(twin: DeviceTwin) -> None:
    if twin.state != DeviceState.SUSPECT or len(twin.history) < DIAGNOSIS_MIN_HISTORY:
        return

    score, point_z, baseline_z = score_device(twin)
    latest = twin.latest().values
    env = ("battery", "signal_strength", "packet_loss")

    signal = latest.get("signal_strength", 100)
    packet_loss = latest.get("packet_loss", 0)

    non_env = [m for m in latest if m not in env]
    instant_metrics = [m for m in non_env if point_z.get(m, 0) >= POINT_Z_THRESHOLD]
    drifting_metrics = [
        m for m in non_env
        if baseline_z.get(m, 0) >= BASELINE_Z_THRESHOLD and point_z.get(m, 0) < POINT_Z_THRESHOLD
    ]

    cause: Optional[str] = None
    confidence = 0.0
    reason = ""

    if signal < 70 or packet_loss >= 10:
        cause = "NETWORK_FAILURE"
        confidence = min(1.0, (packet_loss / 100) + (1 - signal / 100))
        reason = f"signal_strength dropped to {signal:.0f}% and packet_loss reached {packet_loss:.0f}% — classic connectivity breakdown."

    elif len(instant_metrics) >= 2:
        cause = "MALICIOUS_TAMPERING"
        confidence = min(1.0, sum(point_z[m] for m in instant_metrics) / (6 * len(instant_metrics)))
        reason = (
            f"{len(instant_metrics)} metrics ({', '.join(instant_metrics)}) jumped to implausible "
            f"values in a single tick while signal_strength stayed normal ({signal:.0f}%) — "
            f"inconsistent with a physical fault, consistent with spoofed/injected data."
        )

    elif len(instant_metrics) == 1:
        metric = instant_metrics[0]
        cause = "HARDWARE_FAULT"
        confidence = min(1.0, point_z[metric] / 6)
        reason = f"{metric} jumped instantly to an out-of-range value ({latest.get(metric)}) while every other metric on this device stayed normal — points to a single sensor/board fault."

    elif drifting_metrics:
        metric = drifting_metrics[0]
        cause = "SENSOR_DRIFT"
        confidence = min(1.0, baseline_z[metric] / 8)
        reason = (
            f"{metric} has wandered {baseline_z[metric]:.1f} calibration-std away from its original "
            f"baseline value, moving gradually (no sudden jump) — looks like calibration drift, not a fault."
        )

    else:
        cause = "UNCLASSIFIED_ANOMALY"
        confidence = score
        reason = "Anomaly score crossed the threshold but no single signal pattern matched a known fault class yet — flagged for continued observation."

    twin.root_cause = cause
    twin.root_cause_confidence = round(confidence, 3)
    if confidence >= 0.4 or cause == "NETWORK_FAILURE":
        twin.state = DeviceState.ANOMALOUS
        twin.recovery_log.append(f"[DIAGNOSIS] {cause} (conf {confidence:.2f}): {reason}")
