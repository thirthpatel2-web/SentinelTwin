"""
diagnosis.py
------------
Evidence-based, explainable root-cause arbitration.

Instead of a single if/else chain that commits to one answer, every
SUSPECT device gets a set of named, human-readable EVIDENCE values, each
of which adds or subtracts points for each hypothesis. The points are a
log-odds style score; a softmax turns them into probabilities. The
output is therefore:

  - a probability per cause (so the response layer can act under
    uncertainty instead of pretending it is certain), and
  - the exact list of evidence lines that moved the decision.

Causes:
  HARDWARE_FAULT      single-metric jump, stuck value, or dropout with a healthy link
  NETWORK_FAILURE     own link degraded (signal down, packet loss up)
  UPSTREAM_FAILURE    link degraded because the zone GATEWAY failed (symptom, not cause)
  GATEWAY_FAILURE     a gateway whose own load collapsed while its children lost links
  SENSOR_DRIFT        slow residual growth vs. the zone consensus, physically plausible
  MALICIOUS_TAMPERING several sensed metrics jump implausibly at once
  STEALTHY_TAMPERING  drift-shaped residual growth that ALSO shows attack evidence:
                      a rate no aging sensor drifts at, values that stopped tracking
                      the room's physics, transport-provenance anomalies, or failed MACs
  UNCLASSIFIED_ANOMALY nothing matched yet
(DOS_FLOOD_ATTACK and IDENTITY_SPOOFING are decided at ingestion - see security.py.)

The key honest property: when an attacker modifies the TRUE reading at a
plausible rate with valid credentials (a compromised device), none of the
attack-only evidence exists, and the arbitration correctly reports it is
most likely drift - with the attack hypothesis still carrying weight.
The evaluation measures exactly where that boundary lies.
"""

from __future__ import annotations
import math
import statistics
from typing import Dict, List, Optional, Tuple

import clock
from config import PipelineConfig
from digital_twin import DeviceTwin, DeviceState, DigitalTwinRegistry, ENV_METRICS
import security

POINT_Z_THRESHOLD = 2.5
RESIDUAL_Z_THRESHOLD = 3.0
SLOPE_WINDOW = 15
COMOVE_WINDOW = 30
COMOVE_MIN_ENV_STD = 0.12
CONFIRM_PROBABILITY = 0.5         # below this the device stays SUSPECT and keeps observing
MAX_SUSPECT_SECONDS = 20.0        # ...but not forever

CAUSES = ["HARDWARE_FAULT", "NETWORK_FAILURE", "UPSTREAM_FAILURE", "GATEWAY_FAILURE",
          "SENSOR_DRIFT", "MALICIOUS_TAMPERING", "STEALTHY_TAMPERING", "UNCLASSIFIED_ANOMALY"]
# prior log-odds: benign drift is more common in the field than a drift-shaped attack
PRIOR = {c: 0.0 for c in CAUSES}
PRIOR["STEALTHY_TAMPERING"] = -0.7
PRIOR["UNCLASSIFIED_ANOMALY"] = 1.0


def _slope(series: List[float]) -> float:
    n = len(series)
    if n < 4:
        return 0.0
    xm = (n - 1) / 2
    ym = sum(series) / n
    num = sum((i - xm) * (y - ym) for i, y in enumerate(series))
    den = sum((i - xm) ** 2 for i in range(n))
    return num / den if den else 0.0


def _detrend(series: List[float]) -> List[float]:
    b = _slope(series)
    xm = (len(series) - 1) / 2
    ym = sum(series) / len(series)
    return [y - (ym + b * (i - xm)) for i, y in enumerate(series)]


def _corr(a: List[float], b: List[float]) -> Optional[float]:
    if len(a) < 6:
        return None
    sa, sb = statistics.pstdev(a), statistics.pstdev(b)
    if sa == 0 or sb == 0:
        return None
    ma, mb = statistics.fmean(a), statistics.fmean(b)
    return sum((x - ma) * (y - mb) for x, y in zip(a, b)) / (len(a) * sa * sb)


def drift_features(twin: DeviceTwin, metric: str) -> Tuple[float, Optional[float]]:
    """(slope of the residual in residual-sigma per reading, co-movement with the zone physics)."""
    res = [r[metric] for r in list(twin.residuals)[-SLOPE_WINDOW:] if metric in r]
    sd = twin.baseline_std.get(f"r:{metric}", 1.0)
    slope = abs(_slope(res)) / sd if res else 0.0
    pairs = [(c.get(f"v:{metric}"), c.get(metric)) for c in list(twin.consensus_seen)[-COMOVE_WINDOW:]]
    pairs = [(d, c) for d, c in pairs if d is not None and c is not None]
    comove = None
    if len(pairs) >= 8:
        dev = _detrend([d for d, _ in pairs])
        env = _detrend([c for _, c in pairs])
        if statistics.pstdev(env) >= COMOVE_MIN_ENV_STD:
            comove = _corr(dev, env)
    return slope, comove


def _zone_link_context(twin: DeviceTwin, registry: DigitalTwinRegistry) -> Tuple[float, Optional[DeviceTwin]]:
    """Fraction of devices sharing this device's gateway with link symptoms, and that gateway."""
    gw_id = twin.gateway_id if twin.device_type != "gateway" else twin.device_id
    peers = [d for d in registry.all() if d.gateway_id == gw_id and d.device_id != twin.device_id]
    if not peers:
        return 0.0, registry.get(gw_id) if gw_id else None
    bad = 0
    for d in peers:
        latest = d.latest()
        stale = d.last_seen is None or clock.now() - d.last_seen > 4.0
        if stale or (latest and (latest.values.get("signal_strength", 100) < 70
                                 or latest.values.get("packet_loss", 0) >= 10)):
            bad += 1
    return bad / len(peers), registry.get(gw_id) if gw_id else None


def collect_evidence(twin: DeviceTwin, registry: DigitalTwinRegistry, cfg: PipelineConfig) -> Dict[str, float]:
    latest = twin.latest().values if twin.latest() else {}
    recent = list(twin.history)[-6:]
    signals = [r.values.get("signal_strength", 100) for r in recent]
    losses = [r.values.get("packet_loss", 0) for r in recent]
    non_env_point = {m: z for m, z in twin.last_point_z.items() if m not in ENV_METRICS}
    jumps = [m for m, z in non_env_point.items() if z >= POINT_Z_THRESHOLD]
    resid = {m: z for m, z in twin.last_residual_z.items() if z >= RESIDUAL_Z_THRESHOLD and m not in jumps}
    base = {m: z for m, z in twin.last_baseline_z.items()
            if z >= RESIDUAL_Z_THRESHOLD and m not in ENV_METRICS and m not in jumps}

    ev: Dict[str, float] = {
        "jump_metrics": float(len(jumps)),
        "jump_max_z": max(non_env_point.values(), default=0.0),
        "signal": statistics.median(signals) if signals else 100.0,
        "packet_loss": max(losses) if losses else 0.0,
        "dropout": twin.evidence.get("dropout", 0.0),
        "stuck": twin.evidence.get("stuck", 0.0),
        "residual_metrics": float(len(resid)),
        "residual_max_z": max(twin.last_residual_z.values(), default=0.0),
        "baseline_only_metrics": float(len(base)),
        "trust": twin.trust_score,
    }
    worst = max(resid, key=resid.get) if resid else (max(base, key=base.get) if base else None)
    if worst and worst in twin.last_residual_z:
        slope, comove = drift_features(twin, worst)
        ev["slope"] = round(slope, 3)
        if comove is not None:
            ev["comovement"] = round(comove, 3)
    if cfg.use_provenance:
        ev["provenance_rate"] = round(security.provenance_rate(twin), 3)
        ev["auth_failures"] = float(sum(1 for t in twin.auth_failures if clock.now() - t <= 30))
    frac, gw = _zone_link_context(twin, registry)
    ev["zone_link_fraction"] = round(frac, 3)
    if twin.device_type == "gateway":
        ev["gateway_self_degraded"] = float(bool(jumps) and latest.get("throughput_mbps", 120) < 40)
    else:
        ev["gateway_suspect"] = float(bool(gw and gw.state not in (DeviceState.NORMAL, DeviceState.RECOVERED)))
    return ev


def score_hypotheses(ev: Dict[str, float], cfg: PipelineConfig) -> Tuple[Dict[str, float], List[str]]:
    s = dict(PRIOR)
    why: List[str] = []

    def add(cause: str, pts: float, reason: str) -> None:
        s[cause] += pts
        why.append(f"{'+' if pts >= 0 else ''}{pts:.1f} {cause}: {reason}")

    link_bad = ev["signal"] < 70 or ev["packet_loss"] >= 10
    upstream = ev.get("zone_link_fraction", 0) >= 0.5 and (ev.get("gateway_suspect", 0) or ev["zone_link_fraction"] >= 0.75)
    if ev.get("gateway_self_degraded"):
        add("GATEWAY_FAILURE", 3.0, "gateway throughput collapsed under saturated CPU")
        if ev.get("zone_link_fraction", 0) >= 0.5:
            add("GATEWAY_FAILURE", 2.5, f"{ev['zone_link_fraction']:.0%} of its child devices lost their link at the same time")
    if link_bad and upstream:
        add("UPSTREAM_FAILURE", 4.5, f"{ev['zone_link_fraction']:.0%} of devices behind the same gateway degraded together")
        add("NETWORK_FAILURE", -1.5, "a shared upstream cause explains this better than a per-device link fault")
    elif link_bad:
        add("NETWORK_FAILURE", 3.5, f"signal {ev['signal']:.0f}% / packet loss {ev['packet_loss']:.0f}%")
    if ev["dropout"] >= 0.5:
        if link_bad:
            add("NETWORK_FAILURE", 1.0, f"{ev['dropout']:.0%} of readings missing on a degraded link")
        else:
            add("HARDWARE_FAULT", 3.5, f"{ev['dropout']:.0%} of readings missing while the link is healthy (signal {ev['signal']:.0f}%)")
    if ev["stuck"]:
        add("HARDWARE_FAULT", 3.5, "a normally noisy metric repeated the exact same value for 8+ readings")

    if ev["jump_metrics"] == 1 and not link_bad:
        add("HARDWARE_FAULT", 3.0, f"one metric jumped (z={ev['jump_max_z']:.1f}) while the others stayed normal")
    if ev["jump_metrics"] >= 2 and not ev.get("gateway_self_degraded"):
        add("MALICIOUS_TAMPERING", 3.5, f"{int(ev['jump_metrics'])} sensed metrics jumped together in one reading")
        add("HARDWARE_FAULT", -1.0, "a single failing sensor rarely moves several quantities at once")
        if not link_bad:
            add("MALICIOUS_TAMPERING", 0.5, "link quality stayed suspiciously perfect")

    slow = ev["residual_metrics"] + ev["baseline_only_metrics"]
    if slow and ev["jump_metrics"] == 0:
        what = "the zone consensus" if ev["residual_metrics"] else "its own calibration baseline"
        add("SENSOR_DRIFT", 3.0, f"gradual departure from {what} (z={max(ev['residual_max_z'], 0):.1f}) with no sudden jump")
        add("STEALTHY_TAMPERING", 3.0, "drift-shaped departures are also what a careful false-data injection looks like")
        if slow >= 2:
            add("STEALTHY_TAMPERING", 1.0, "several channels drifting at once is unusual for physical aging")
        if cfg.use_rate_prior and "slope" in ev:
            bound = cfg.max_plausible_drift
            if ev["slope"] > bound:
                excess = min(3.0, 1.5 * (ev["slope"] / bound - 1) + 1.0)
                add("STEALTHY_TAMPERING", excess, f"residual grows {ev['slope']:.2f} sd/reading, faster than the {bound:.2f} physical aging bound")
                add("SENSOR_DRIFT", -excess, "real sensors do not age this fast")
            else:
                add("SENSOR_DRIFT", 0.8, f"growth rate {ev['slope']:.2f} sd/reading is within the physical aging bound")
        if cfg.use_comovement and "comovement" in ev:
            c = ev["comovement"]
            if c < cfg.comove_threshold:
                add("STEALTHY_TAMPERING", cfg.comove_weight, f"readings stopped tracking the room's physics (co-movement r={c:.2f})")
                add("SENSOR_DRIFT", -0.8 * cfg.comove_weight, "a drifting sensor still follows the environment it measures")
            elif c >= 0.4:
                add("SENSOR_DRIFT", 1.0, f"readings still follow the room's physics (r={c:.2f})")

    if cfg.use_provenance:
        if ev.get("auth_failures", 0) > 0:
            add("STEALTHY_TAMPERING", 4.0, f"{int(ev['auth_failures'])} messages failed authentication")
            add("MALICIOUS_TAMPERING", 2.0, "messages failed authentication")
            add("SENSOR_DRIFT", -3.0, "aging does not forge message authentication codes")
        if ev.get("provenance_rate", 0) >= 0.15:
            add("STEALTHY_TAMPERING", 3.0, f"sequence/publisher conflicts on {ev['provenance_rate']:.0%} of messages - a second source is publishing")
            add("SENSOR_DRIFT", -2.5, "a drifting sensor does not change its transport fingerprint")

    if ev["trust"] < 0.35:
        add("MALICIOUS_TAMPERING", 1.0, f"repeat offender (trust {ev['trust']:.2f})")
    return s, why


def softmax(scores: Dict[str, float]) -> Dict[str, float]:
    m = max(scores.values())
    exp = {k: math.exp(v - m) for k, v in scores.items()}
    z = sum(exp.values())
    return {k: v / z for k, v in exp.items()}


def diagnose(twin: DeviceTwin, registry: DigitalTwinRegistry, cfg: PipelineConfig, force: bool = False) -> bool:
    """Updates twin.posterior / root_cause / explanation. Returns True if the diagnosis is confirmed."""
    if not force and (twin.state != DeviceState.SUSPECT or len(twin.history) < 3):
        return False
    ev = collect_evidence(twin, registry, cfg)
    scores, why = score_hypotheses(ev, cfg)
    post = softmax(scores)
    cause = max(post, key=post.get)
    twin.evidence.update(ev)
    twin.posterior = post
    twin.root_cause = cause
    twin.root_cause_confidence = round(post[cause], 3)
    twin.explanation = why or ["no known fault signature matched"]
    if force:
        return True
    waited = clock.now() - (twin.suspect_since or clock.now())
    if (post[cause] >= CONFIRM_PROBABILITY and cause != "UNCLASSIFIED_ANOMALY") or waited >= MAX_SUSPECT_SECONDS:
        twin.state = DeviceState.ANOMALOUS
        top = ", ".join(f"{c} {p:.0%}" for c, p in sorted(post.items(), key=lambda kv: -kv[1])[:3])
        twin.recovery_log.append(f"[DIAGNOSIS] {cause} ({top}) - " + "; ".join(why[:4]))
        return True
    return False
