"""
anomaly_detector.py
--------------------
Real-time anomaly scoring per device from simple, transparent statistics
(no black-box model, so every flag can be explained):

  1. POINT score - rolling z-score per metric against the last ~9
     readings. Catches SUDDEN changes: hardware spikes, injected values,
     signal collapse. Blind to slow change, because the window moves with
     the signal.

  2. RESIDUAL score - z-score of the device's residual against its zone
     consensus (consensus.py), relative to the device's own frozen
     calibration offset. Catches slow drift and slow tampering, and -
     unlike a raw baseline - does NOT fire when the whole room really
     changes, because the peers move too.

  3. BASELINE score - z-score against a frozen per-device calibration
     snapshot. Used only for metrics with no peer group (motion,
     gateway load), or for every metric when consensus is ablated.

  4. STUCK - a metric that normally carries noise repeats the exact same
     value for many readings (frozen ADC / hung sensor driver).

  5. DROPOUT - the fraction of expected readings that never arrived
     over the recent window (a dead or intermittently failing sensor).

Whichever signal is strongest decides whether the device is flagged
SUSPECT; diagnosis.py then reads the shape of all of them together.
"""

from __future__ import annotations
import statistics
from typing import Dict, List, Tuple

import clock
from config import PipelineConfig
from digital_twin import DeviceTwin, DeviceState, ENV_METRICS, QUANTITY_OF

ANOMALY_THRESHOLD = 0.6
SUSPECT_MIN_HISTORY = 10          # warm-up before the rolling window is trusted
BASELINE_CALIBRATION_TICKS = 20   # clean history frozen as the calibration snapshot
RESIDUAL_CALIBRATION_TICKS = 20
MIN_STDEV_FLOOR_RATIO = 0.02      # small magnitude-relative floor; the real floor is each device's measured noise
MIN_STDEV_FLOOR_ABS = 0.05
STUCK_RUN = 8
DROPOUT_WINDOW_SECONDS = 15.0
DEFAULT_INTERVAL = 1.5
Z_SCALE = 8.3                     # threshold 0.6 ~ z 5: rare enough to run unattended on a fleet
RESIDUAL_SMOOTH = 3               # residual z is taken on the mean of the last 3 readings


def _stats(values: List[float]) -> Tuple[float, float]:
    if len(values) < 2:
        v = values[0] if values else 0.0
        return v, max(MIN_STDEV_FLOOR_ABS, abs(v) * MIN_STDEV_FLOOR_RATIO)
    mean = statistics.fmean(values)
    floor = max(MIN_STDEV_FLOOR_ABS, abs(mean) * MIN_STDEV_FLOOR_RATIO)
    return mean, max(statistics.pstdev(values), floor)


def _maybe_capture_baseline(twin: DeviceTwin) -> None:
    """Freeze calibration snapshots the first time there is enough clean history."""
    if "_raw" not in twin.baseline_mean and len(twin.history) >= BASELINE_CALIBRATION_TICKS:
        window = list(twin.history)[-BASELINE_CALIBRATION_TICKS:]
        for metric in window[-1].values:
            vals = [r.values[metric] for r in window if metric in r.values]
            if len(vals) < 3:
                continue
            mean, stdev = _stats(vals)
            noise = statistics.stdev(vals) * 1.15     # sample std, inflated: a 20-reading estimate runs low
            twin.baseline_mean[metric] = mean
            twin.baseline_std[metric] = max(stdev, noise)
            twin.baseline_std[f"n:{metric}"] = noise
        twin.baseline_mean["_raw"] = 1.0
    if "_res" not in twin.baseline_mean and len(twin.residuals) >= RESIDUAL_CALIBRATION_TICKS:
        window = list(twin.residuals)[-RESIDUAL_CALIBRATION_TICKS:]
        for metric in window[-1]:
            vals = [r[metric] for r in window if metric in r]
            if len(vals) < 5:
                continue
            noise = twin.baseline_std.get(f"n:{metric}", 0.1)
            twin.baseline_mean[f"r:{metric}"] = statistics.fmean(vals)
            # a residual can never be less noisy than the device itself (plus the consensus' own noise)
            twin.baseline_std[f"r:{metric}"] = max(statistics.pstdev(vals), 1.2 * noise, MIN_STDEV_FLOOR_ABS)
            if metric not in twin.ref_offset:
                twin.ref_offset[metric] = (twin.baseline_mean[f"r:{metric}"], twin.baseline_std[f"r:{metric}"])
        twin.baseline_mean["_res"] = 1.0


def residual_z(twin: DeviceTwin) -> Dict[str, float]:
    if not twin.residuals or "_res" not in twin.baseline_mean:
        return {}
    out = {}
    recent = list(twin.residuals)[-RESIDUAL_SMOOTH:]
    for metric in twin.residuals[-1]:
        vals = [x[metric] for x in recent if metric in x]
        r = sum(vals) / len(vals)
        key = f"r:{metric}"
        if key in twin.baseline_mean:
            z = abs(r - twin.baseline_mean[key]) / twin.baseline_std[key]
            if metric in twin.ref_offset:
                ref_mean, ref_sd = twin.ref_offset[metric]
                z = max(z, abs(r - ref_mean) / ref_sd)   # re-learning cannot hide an offset
            out[metric] = round(z, 2)
    return out


def expected_interval(twin: DeviceTwin) -> float:
    ts = [r.timestamp for r in list(twin.history)[-12:]]
    iats = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(iats) >= 5:
        return max(0.2, statistics.median(iats))
    return DEFAULT_INTERVAL


def dropout_rate(twin: DeviceTwin) -> float:
    """Fraction of readings expected over the recent window that never arrived."""
    now = clock.now()
    if twin.last_seen is None or now - twin.active_since < DROPOUT_WINDOW_SECONDS:
        return 0.0
    got = len({round(r.timestamp, 1) for r in twin.history if now - r.timestamp <= DROPOUT_WINDOW_SECONDS})
    expected = DROPOUT_WINDOW_SECONDS / expected_interval(twin)
    return max(0.0, min(1.0, 1.0 - got / expected))


def stuck_metrics(twin: DeviceTwin) -> List[str]:
    if len(twin.history) < STUCK_RUN:
        return []
    recent = list(twin.history)[-STUCK_RUN:]
    out = []
    for metric in recent[-1].values:
        if metric in ENV_METRICS:
            continue
        if twin.baseline_std.get(f"n:{metric}", 0.0) < 0.02:
            continue  # metric never carried noise - constant is normal for it
        vals = [r.values.get(metric) for r in recent]
        if None not in vals and len(set(vals)) == 1:
            out.append(metric)
    return out


def _residual_jump_z(twin: DeviceTwin, metric: str, current_val: float):
    """Point z-score of the device's residual against its peers, or None if there is no peer view."""
    if not twin.residuals or not twin.consensus_seen:
        return None
    if twin.consensus_seen[-1].get(f"v:{metric}") != current_val:
        return None   # the latest residual is not for this reading (no peers this tick)
    series = [r[metric] for r in list(twin.residuals)[-SUSPECT_MIN_HISTORY:] if metric in r]
    if len(series) < 4:
        return None
    past, cur = series[:-1], series[-1]
    mean = statistics.fmean(past)
    floor = twin.baseline_std.get(f"r:{metric}", 1.2 * twin.baseline_std.get(f"n:{metric}", MIN_STDEV_FLOOR_ABS))
    return round(abs(cur - mean) / max(statistics.pstdev(past), floor), 2)


def score_device(twin: DeviceTwin, cfg: PipelineConfig) -> float:
    """Computes and stores every z-score on the twin; returns the overall 0..1 score."""
    _maybe_capture_baseline(twin)   # always captured (stuck detection needs the noise level)

    twin.last_point_z, twin.last_baseline_z, twin.last_residual_z = {}, {}, {}
    drop = dropout_rate(twin)
    stuck = stuck_metrics(twin)
    twin.evidence["dropout"] = round(drop, 3)
    twin.evidence["stuck"] = float(len(stuck))

    components = [0.8 if stuck else 0.0, 0.75 if drop >= 0.5 else drop * 0.8]
    if len(twin.history) < max(SUSPECT_MIN_HISTORY, BASELINE_CALIBRATION_TICKS) or "_raw" not in twin.baseline_mean:
        return max(components)   # still calibrating

    readings = list(twin.history)
    recent_window = readings[-SUSPECT_MIN_HISTORY:-1]
    latest = readings[-1].values
    if cfg.use_consensus:
        twin.last_residual_z = residual_z(twin)

    for metric, current_val in latest.items():
        past = [r.values[metric] for r in recent_window if metric in r.values]
        if len(past) >= 3:
            mean, stdev = _stats(past)
            noise_key = f"n:{metric}"
            stdev = max(stdev, twin.baseline_std.get(noise_key, 0.0))   # short windows underestimate noise
            z = abs(current_val - mean) / stdev
            twin.last_point_z[metric] = round(z, 2)
            if noise_key in twin.baseline_std and z < 4 and twin.state in (DeviceState.NORMAL, DeviceState.RECOVERED):
                # running noise estimate (~50-reading memory) - far steadier than one calibration window
                dev2 = (current_val - mean) ** 2 * (len(past) / (len(past) + 1))
                twin.baseline_std[noise_key] = (0.98 * twin.baseline_std[noise_key] ** 2 + 0.02 * dev2) ** 0.5
        jump = _residual_jump_z(twin, metric, current_val) if cfg.use_consensus else None
        if jump is not None:
            # with peers, a sudden change is judged RELATIVE to the room: when the HVAC kicks in every
            # sensor jumps together and the residual stays flat; a failing or forged sensor jumps alone
            twin.last_point_z[metric] = jump
        has_peer_view = metric in twin.last_residual_z
        if cfg.use_frozen_baseline and metric in twin.baseline_mean and not has_peer_view:
            z = abs(current_val - twin.baseline_mean[metric]) / max(twin.baseline_std[metric],
                                                                 twin.baseline_std.get(f"n:{metric}", 0.0))
            if cfg.use_consensus and metric in QUANTITY_OF:
                # a physical quantity with no peers this tick: its environment can move legitimately,
                # so a per-device baseline is weak evidence (honest limit, not a detector)
                z *= 0.5
            twin.last_baseline_z[metric] = round(z, 2)

    zs = [max(twin.last_point_z.values(), default=0.0),
          max(twin.last_baseline_z.values(), default=0.0),
          max(twin.last_residual_z.values(), default=0.0)]
    components.append(min(1.0, max(zs) / Z_SCALE))
    return round(max(components), 3)


def evaluate(twin: DeviceTwin, cfg: PipelineConfig) -> None:
    """Updates twin.last_anomaly_score and moves NORMAL/RECOVERED <-> SUSPECT."""
    if twin.state == DeviceState.ISOLATED:
        return
    score = score_device(twin, cfg)
    twin.last_anomaly_score = score
    if twin.state not in (DeviceState.NORMAL, DeviceState.RECOVERED, DeviceState.SUSPECT):
        return
    if score >= ANOMALY_THRESHOLD:
        if twin.state != DeviceState.SUSPECT:
            twin.state = DeviceState.SUSPECT
            twin.suspect_since = clock.now()
    elif twin.state == DeviceState.SUSPECT:
        # false alarm / transient noise - stand down
        twin.state = DeviceState.NORMAL
        twin.suspect_since = None
        twin.root_cause = None
        twin.root_cause_confidence = 0.0
