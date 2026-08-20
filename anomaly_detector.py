"""
anomaly_detector.py
--------------------
Real-time anomaly scoring per device, combining two complementary signals:

  1. POINT score - rolling z-score per metric against a short recent
     window (last ~10 ticks). Catches SUDDEN changes: a hardware spike,
     a malicious injection, a signal collapse. Fast to react, but blind
     to slow drift because the window itself drifts along with a slowly
     moving signal.

  2. BASELINE score - z-score of the latest value against a FROZEN
     calibration snapshot (mean/std) captured once, early in the
     device's life, before any drift has accumulated. This is what
     actually exposes slow SENSOR_DRIFT, which the rolling window can't
     see once the drift is baked into it.

Both are simple, transparent statistics (no black-box model) so the
result stays explainable - a stated requirement of the project.
Whichever score is higher decides whether the device is flagged
SUSPECT; diagnosis.py then looks at the shape of the two scores
together to work out *which* fault class it actually is.
"""

from __future__ import annotations
import statistics
from typing import Dict, List, Tuple

from digital_twin import DeviceTwin, DeviceState

ANOMALY_THRESHOLD = 0.6
SUSPECT_MIN_HISTORY = 10          # warm-up before the rolling window is trusted
BASELINE_CALIBRATION_TICKS = 10   # how much clean history to freeze as calibration
MIN_STDEV_FLOOR_RATIO = 0.18      # floor scales with each metric's own magnitude
MIN_STDEV_FLOOR_ABS = 0.05        # absolute floor for metrics that hover near zero


def _stats(values: List[float]) -> Tuple[float, float]:
    if len(values) < 2:
        v = values[0] if values else 0.0
        return v, max(MIN_STDEV_FLOOR_ABS, abs(v) * MIN_STDEV_FLOOR_RATIO)
    mean = statistics.fmean(values)
    floor = max(MIN_STDEV_FLOOR_ABS, abs(mean) * MIN_STDEV_FLOOR_RATIO)
    stdev = max(statistics.pstdev(values), floor)
    return mean, stdev


def _maybe_capture_baseline(twin: DeviceTwin) -> None:
    """Freeze a calibration snapshot the first time we have enough clean history."""
    if twin.baseline_mean or len(twin.history) < BASELINE_CALIBRATION_TICKS:
        return
    window = list(twin.history)[-BASELINE_CALIBRATION_TICKS:]
    metrics = window[-1].values.keys()
    for metric in metrics:
        vals = [r.values.get(metric) for r in window if metric in r.values]
        vals = [v for v in vals if v is not None]
        if len(vals) < 3:
            continue
        mean, stdev = _stats(vals)
        twin.baseline_mean[metric] = mean
        twin.baseline_std[metric] = stdev


def score_device(twin: DeviceTwin) -> Tuple[float, Dict[str, float], Dict[str, float]]:
    """Returns (overall_score 0..1, per_metric point z-scores, per_metric baseline z-scores)."""
    _maybe_capture_baseline(twin)

    if len(twin.history) < SUSPECT_MIN_HISTORY:
        return 0.0, {}, {}

    readings = list(twin.history)
    recent_window = readings[-SUSPECT_MIN_HISTORY:-1]   # short recent window, excludes newest point
    latest = readings[-1].values

    point_z: Dict[str, float] = {}
    baseline_z: Dict[str, float] = {}

    for metric, current_val in latest.items():
        past_vals = [r.values.get(metric) for r in recent_window if metric in r.values]
        past_vals = [v for v in past_vals if v is not None]
        if len(past_vals) >= 3:
            mean, stdev = _stats(past_vals)
            point_z[metric] = round(abs(current_val - mean) / stdev, 2)

        if metric in twin.baseline_mean:
            b_mean, b_std = twin.baseline_mean[metric], twin.baseline_std[metric]
            baseline_z[metric] = round(abs(current_val - b_mean) / b_std, 2)

    if not point_z and not baseline_z:
        return 0.0, {}, {}

    max_point_z = max(point_z.values(), default=0.0)
    max_baseline_z = max(baseline_z.values(), default=0.0)
    score = min(1.0, max(max_point_z, max_baseline_z) / 7.0)
    return round(score, 3), point_z, baseline_z


def evaluate(twin: DeviceTwin) -> None:
    """Mutates twin.last_anomaly_score and twin.state based on scoring."""
    if twin.state in (DeviceState.ISOLATED, DeviceState.RECOVERING):
        return

    score, _, _ = score_device(twin)
    twin.last_anomaly_score = score

    if score >= ANOMALY_THRESHOLD:
        if twin.state == DeviceState.NORMAL or twin.state == DeviceState.RECOVERED:
            twin.state = DeviceState.SUSPECT
    else:
        if twin.state == DeviceState.SUSPECT:
            # false alarm / transient noise - stand down
            twin.state = DeviceState.NORMAL
            twin.root_cause = None
            twin.root_cause_confidence = 0.0
