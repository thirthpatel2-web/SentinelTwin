"""
experiments/harness.py
----------------------
Runs one reproducible episode of the pipeline on a SimClock with ground
truth, and measures what happened to the injected fault:

  detection     detected?, MTTD (onset -> SUSPECT/ingest catch)
  diagnosis     first and final diagnosed cause vs. ground truth,
                probability the system assigned to the true cause
  response      actions taken, escalations, outcome, MTTR (detect -> verified)
  harm          exposure  - readings that were WRONG yet accepted as trusted data
                outage    - ticks with no trusted data from the device and no standby covering
                false quarantine (a benign fault firewalled), false recovery
                (declared recovered while the fault was still active)
  collateral    incidents and isolations on devices that had nothing wrong

Every episode is fully determined by (scenario, config, seed).
"""

from __future__ import annotations
import random
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import clock                                                   # noqa: E402
from config import PipelineConfig                              # noqa: E402
from digital_twin import DeviceState, ENV_METRICS, QUANTITY_OF  # noqa: E402
from engine import SentinelEngine                              # noqa: E402
from simulator import DEVICE_BLUEPRINT, TICK_SECONDS, ATTACK_MODES, FaultMode, EXPECTED_CAUSE  # noqa: E402

WARMUP_TICKS = 60
RUN_TICKS = 240
EXPOSURE_SIGMA = 5.0   # an honest reading exceeds 5 sigma ~once per 1.7M readings
ISOLATING = ("ACTIVATE_BACKUP", "QUARANTINE", "GATEWAY_FAILOVER")

ELIGIBLE = {
    "HARDWARE": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "STUCK": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "DROPOUT": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "NETWORK": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "GATEWAY": ("gateway",),
    "DRIFT": ("temp_sensor", "humidity_sensor"),
    "TAMPER": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "TAMPER_RAMP": ("temp_sensor", "humidity_sensor"),
    "ON_OFF": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "FLOOD": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "SPOOF": ("temp_sensor", "humidity_sensor", "motion_sensor"),
    "NONE": ("temp_sensor", "humidity_sensor", "motion_sensor"),
}


@dataclass
class Episode:
    fault: str
    seed: int
    params: Dict[str, object] = field(default_factory=dict)
    zone_event: Optional[Dict[str, object]] = None
    run_ticks: int = RUN_TICKS


class Monitor:
    """Per-tick harm accounting for the target device."""

    def __init__(self, engine: SentinelEngine, target: str) -> None:
        self.e, self.target = engine, target
        self.exposure = 0
        self.outage = 0
        self.ticks_with_fault = 0
        self.trust_trace: List[float] = []

    def __call__(self, e: SentinelEngine) -> None:
        twin = e.registry.get(self.target)
        dev = e.sim.get(self.target)
        self.trust_trace.append(twin.trust_score)
        if dev.gt is None:
            return
        self.ticks_with_fault += 1
        now = clock.now()
        fresh = twin.last_seen is not None and now - twin.last_seen < TICK_SECONDS
        trusted_path = (fresh and twin.data_trusted and not twin.firewall_blocked
                        and twin.state not in (DeviceState.ISOLATED, DeviceState.CONTAINED))
        if trusted_path and twin.device_type != "gateway" and twin.latest() is not None:
            env = e.sim.zones[twin.zone]
            bp = DEVICE_BLUEPRINT[twin.device_type]
            for metric, value in twin.latest().values.items():
                if metric in ENV_METRICS or metric not in bp:
                    continue
                q = QUANTITY_OF.get(metric)
                truth = env.T if q == "T" else env.H if q == "H" else bp[metric][0]
                if abs(value - truth) > EXPOSURE_SIGMA * bp[metric][1]:
                    self.exposure += 1
                    break
        if twin.device_type == "gateway":
            # a gateway's "service" is carrying its children: covered once they are re-homed
            covered = not any(d.gateway_id == self.target for d in e.registry.all())
        else:
            covered = any(b.backup_for == self.target and b.last_seen is not None and now - b.last_seen < TICK_SECONDS
                          for b in e.registry.all() if b.is_backup)
        if not trusted_path and not covered:
            self.outage += 1


def pick_target(engine: SentinelEngine, fault: str, rng: random.Random) -> str:
    types = ELIGIBLE[fault]
    cands = sorted(t.device_id for t in engine.registry.all()
                   if t.device_type in types and not t.is_backup and t.zone != "Zone-Live")
    return rng.choice(cands)


def run_episode(ep: Episode, cfg: PipelineConfig, config_name: str = "full", env_traces=None) -> dict:
    clock.use(clock.SimClock(10_000.0))
    engine = SentinelEngine(cfg=cfg, seed=ep.seed, env_traces=env_traces)
    rng = random.Random(ep.seed * 7919 + sum(map(ord, ep.fault)))   # stable across processes (no hash())
    target = pick_target(engine, ep.fault, rng)
    mon = Monitor(engine, target)
    for _ in range(WARMUP_TICKS):
        engine.tick()
    pre_incidents = {i.id for i in engine.incidents.all()}
    onset = clock.now()
    if ep.fault != "NONE":
        engine.inject(target, ep.fault, **ep.params)
    if ep.zone_event:
        engine.zone_event(engine.registry.get(target).zone, **ep.zone_event)
    engine.observers.append(mon)
    for _ in range(ep.run_ticks):
        engine.tick()

    incs = [i for i in engine.incidents.all() if i.id not in pre_incidents]
    mine = [i for i in incs if i.device_id == target]
    others = [i for i in incs if i.device_id != target]
    expected = EXPECTED_CAUSE.get(FaultMode(ep.fault), "NONE") if ep.fault != "NONE" else "NONE"
    is_attack = ep.fault != "NONE" and FaultMode(ep.fault) in ATTACK_MODES
    first = mine[0] if mine else None
    all_actions = [a for i in mine for a in i.actions]
    final_cause = all_actions[-1]["cause"] if all_actions else (first.cause if first else "NONE")
    gw_children = [d.device_id for d in engine.registry.all() if d.gateway_id == target] if ep.fault == "GATEWAY" else []

    rec = {
        "config": config_name, "fault": ep.fault, "seed": ep.seed, "target": target,
        "device_type": engine.registry.get(target).device_type,
        "attacker": ep.params.get("attacker", ""), "slope": ep.params.get("slope", ep.params.get("rate", "")),
        "auth": cfg.use_auth, "zone_event": bool(ep.zone_event),
        "expected": expected, "is_attack": is_attack,
        "detected": first is not None,
        "mttd": round(first.t_detect - onset, 2) if first else None,
        "first_cause": first.cause if first else "NONE",
        "final_cause": final_cause,
        "p_true_first": round(first.posterior.get(expected, 0.0), 3) if first else 0.0,
        "correct_first": (first.cause if first else "NONE") == expected,
        "correct_final": final_cause == expected,
        "actions": "|".join(a["action"] for a in all_actions),
        "n_actions": len(all_actions),
        "escalations": sum(i.escalations for i in mine),
        "outcome": first.outcome if first else "NONE",
        "mttr": round(first.t_verified - first.t_detect, 2) if first and first.t_verified and first.outcome == "RECOVERED" else None,
        "false_recovery": any(i.outcome in ("RECOVERED", "UNVERIFIED_CLOSE") and i.gt_active_at_close for i in mine),
        "false_quarantine": (not is_attack) and any(a["action"] == "QUARANTINE" for a in all_actions),
        "missed_attack_action": is_attack and first is not None and not any(a["action"] == "QUARANTINE" for a in all_actions),
        "reincidents": max(0, len(mine) - 1),
        # an attack that never reached the data (e.g. every forged message failed its MAC) needs no response
        "neutralised": is_attack and first is None and mon.exposure == 0,
        "genuine_dropped": engine.ingestor.genuine_dropped.get(target, 0),
        "exposure_ticks": mon.exposure,
        "outage_ticks": mon.outage,
        "fault_ticks": mon.ticks_with_fault,
        "other_incidents": len([i for i in others if i.device_id not in gw_children]),
        "child_incidents": len([i for i in others if i.device_id in gw_children]),
        "child_isolations": sum(1 for i in others if i.device_id in gw_children
                                for a in i.actions if a["action"] in ISOLATING),
        "min_trust": round(min(mon.trust_trace), 3) if mon.trust_trace else None,
        "mean_trust": round(sum(mon.trust_trace) / len(mon.trust_trace), 3) if mon.trust_trace else None,
        "evidence": first.evidence if first else {},
    }
    if ep.fault == "ON_OFF":
        rec["trust_trace"] = mon.trust_trace[::4]
    return rec
