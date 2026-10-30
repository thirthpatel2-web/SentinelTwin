"""
engine.py
---------
SentinelEngine wires the whole pipeline together and advances it one
tick at a time. The FastAPI server (main.py) runs it on wall-clock time;
the experiment harness (experiments/) runs it on a SimClock, thousands of
ticks per second, with ground truth attached to every incident.

One tick:
  1. simulator emits messages -> ingest (security transport checks)
  2. zone consensus + per-device residuals
  3. anomaly scoring (NORMAL -> SUSPECT)
  4. security fast-path on SUSPECT devices
  5. evidence-based diagnosis (SUSPECT -> ANOMALOUS)
  6. trust update
  7. expected-cost response + recovery actions
  8. post-action verification / escalation
"""

from __future__ import annotations
from collections import deque
from typing import Callable, Deque, Dict, List, Optional, Tuple

import clock
from config import PipelineConfig
from consensus import ZoneConsensus
from digital_twin import DeviceState, DigitalTwinRegistry
from incidents import IncidentLog
from ingest import Ingestor
from recovery import RecoveryEngine
from security import Firewall, RateTracker, fast_attack_check
from simulator import NetworkSimulator, TICK_SECONDS, ATTACK_MODES
import anomaly_detector
import diagnosis
import trust

ENV_CHANGE_THRESHOLD = {"T": 3.0, "H": 5.0}


class SentinelEngine:
    def __init__(self, cfg: Optional[PipelineConfig] = None, seed: Optional[int] = None,
                 simulate: bool = True, env_traces=None, zones=("Zone-A", "Zone-B", "Zone-C"),
                 max_events: int = 300) -> None:
        self.cfg = cfg or PipelineConfig()
        self.registry = DigitalTwinRegistry()
        self.firewall = Firewall(permanent=self.cfg.permanent_block)
        self.rate = RateTracker(mode=self.cfg.rate_detector)
        self.incidents = IncidentLog()
        self.consensus = ZoneConsensus()
        self.events: List[dict] = []
        self.max_events = max_events
        self.tick_n = 0
        self.sim: Optional[NetworkSimulator] = None
        if simulate:
            self.sim = NetworkSimulator(self.registry, seed=seed, use_auth=self.cfg.use_auth, env_traces=env_traces)
            self.sim.build_default_network(zones=zones)
        self.recovery = RecoveryEngine(self.registry, self.firewall, self.incidents, self.cfg,
                                       self.log_event, sim=self.sim, ground_truth=self.ground_truth)
        self.ingestor = Ingestor(self.registry, self.firewall, self.rate, self.cfg, self.log_event, self.recovery)
        self._env_flagged: Dict[str, bool] = {}
        self.observers: List[Callable[["SentinelEngine"], None]] = []
        self.inbox: Deque = deque()   # real-hardware messages queued by the MQTT thread
        self.mqtt_client = None

    # ---- logging / ground truth ------------------------------------------
    def log_event(self, kind: str, device_id: str, message: str) -> None:
        self.events.append({"ts": round(clock.now(), 2), "kind": kind, "device_id": device_id, "message": message})
        if len(self.events) > self.max_events:
            del self.events[: len(self.events) - self.max_events]

    def ground_truth(self, device_id: str) -> Optional[Tuple[str, str, float, bool]]:
        """(mode, expected cause, onset, is_attack) of what is really wrong with a device, if anything."""
        if self.sim is None:
            return None
        dev = self.sim.get(device_id)
        if dev and dev.gt is not None:
            gt = dev.gt
            return gt.mode.value, gt.expected_cause, gt.onset, gt.mode in ATTACK_MODES
        twin = self.registry.get(device_id)
        if twin and twin.gateway_id:
            gw = self.sim.get(twin.gateway_id)
            if gw and gw.gt is not None and gw.gt.mode.value == "GATEWAY":
                return "UPSTREAM", "UPSTREAM_FAILURE", gw.gt.onset, False
        return None

    # ---- one tick -------------------------------------------------------
    def tick(self) -> None:
        self.tick_n += 1
        tick_start = clock.now()
        if self.sim is not None:
            self.sim.tick_all(self.ingestor.ingest)
        while self.inbox:                       # deque.popleft is atomic: safe against the MQTT thread
            self.ingestor.ingest(self.inbox.popleft(), is_real=True)
        self.consensus.update(self.registry, tick_start, self.cfg)
        self._check_zone_environment()

        for twin in self.registry.all():
            prev_state = twin.state
            prev_log = len(twin.recovery_log)
            fresh = twin.last_seen is not None and twin.last_seen >= tick_start

            anomaly_detector.evaluate(twin, self.cfg)
            if twin.state == DeviceState.SUSPECT and prev_state != DeviceState.SUSPECT:
                self.log_event("ANOMALY", twin.device_id, f"Anomaly suspected (score={twin.last_anomaly_score:.2f}).")

            if twin.state == DeviceState.SUSPECT:
                blocked = fast_attack_check(twin, self.firewall) if self.cfg.security_layer else None
                if blocked is None:
                    diagnosis.diagnose(twin, self.registry, self.cfg)

            trust.update_trust(twin, self.cfg.trust_model)
            self.recovery.handle_anomalous(twin)
            self.recovery.progress(twin, fresh)

            for new_msg in twin.recovery_log[prev_log:]:
                kind = ("FIREWALL" if new_msg.startswith("[FIREWALL]") else
                        "DIAGNOSIS" if new_msg.startswith("[DIAGNOSIS]") else "RECOVERY")
                if "VERIFIED" in new_msg:
                    kind = "VERIFIED"
                self.log_event(kind, twin.device_id, new_msg.split("] ", 1)[-1])

        for obs in self.observers:
            obs(self)
        cur = clock.current()
        if hasattr(cur, "advance"):
            cur.advance(TICK_SECONDS)

    def _check_zone_environment(self) -> None:
        for zone in list(self.consensus.zone_values):
            shift = self.consensus.zone_shift(zone)
            big = {q: d for q, d in shift.items() if abs(d) >= ENV_CHANGE_THRESHOLD.get(q, 3.0)}
            if big and not self._env_flagged.get(zone):
                self._env_flagged[zone] = True
                n = sum(1 for d in self.registry.in_zone(zone) if d.state in (DeviceState.NORMAL, DeviceState.RECOVERED))
                desc = ", ".join(f"{'temperature' if q == 'T' else 'humidity'} {d:+.1f}" for q, d in big.items())
                self.log_event("INFO", zone, f"Zone-wide ENVIRONMENT CHANGE ({desc}) - {n} co-located sensors agree, "
                               f"so this is the room changing, not a device fault. No action taken.")
            elif not big and self._env_flagged.get(zone):
                self._env_flagged[zone] = False

    # ---- operator / demo API --------------------------------------------
    def inject(self, device_id: str, fault: str, **params) -> None:
        from simulator import FaultMode
        dev = self.sim.get(device_id) if self.sim else None
        if dev is None:
            raise KeyError(device_id)
        dev.inject_fault(FaultMode(fault.upper()), **params)
        self.log_event("INFO", device_id, f"Fault injected: {fault.upper()}" + (f" {params}" if params else ""))

    def zone_event(self, zone: str, **kw) -> None:
        self.sim.start_zone_event(zone, **kw)
        self.log_event("INFO", zone, f"Physical zone event started (heatwave {kw.get('magnitude_t', 5.0):+.1f} degC).")

    def clear(self, device_id: str) -> None:
        dev = self.sim.get(device_id) if self.sim else None
        if dev:
            dev.clear_fault()
        twin = self.registry.get(device_id)
        if twin:
            self.recovery._release_backup(twin)
            for key in (device_id,):
                self.firewall.unblock(key)
            twin.state = DeviceState.NORMAL
            twin.root_cause, twin.root_cause_confidence = None, 0.0
            twin.posterior, twin.explanation = {}, []
            twin.firewall_blocked, twin.firewall_reason = False, None
            twin.data_trusted = True
            twin.incident_id, twin.current_action, twin.repair_eta = None, None, None
            twin.suspect_since = None
            twin.reset_learning()
        self.log_event("INFO", device_id, "Manually cleared and reset to NORMAL.")

    def stats(self) -> dict:
        """Fleet-level KPIs for the dashboard header."""
        incs = self.incidents.all()
        closed = [i for i in incs if i.outcome == "RECOVERED" and i.t_verified]
        mttr = sorted(i.t_verified - i.t_detect for i in closed)
        attacks = [i for i in incs if any(a["action"] == "QUARANTINE" for a in i.actions)]
        twins = self.registry.all()
        return {
            "devices": len(twins),
            "healthy": sum(1 for t in twins if t.state in (DeviceState.NORMAL, DeviceState.RECOVERED)),
            "incidents": len(incs),
            "open": sum(1 for i in incs if i.outcome == "OPEN"),
            "recovered": len(closed),
            "attacks_contained": len(attacks),
            "median_mttr": round(mttr[len(mttr) // 2], 1) if mttr else None,
            "active_blocks": sum(1 for k in list(self.firewall._blocks) if self.firewall.is_blocked(k)),
            "messages_dropped": self.ingestor.dropped,
            "distrusted": sum(1 for t in twins if not t.data_trusted),
        }

    def snapshot(self) -> dict:
        # trust history is kept here (dashboard only), so experiment runs pay nothing for it
        hist = getattr(self, "_trust_hist", None)
        if hist is None:
            hist = self._trust_hist = {}
        for t in self.registry.all():
            h = hist.setdefault(t.device_id, deque(maxlen=60))
            h.append(round(t.trust_score, 3))
        return {
            "devices": self.registry.snapshot(),
            "trust_history": {k: list(v) for k, v in hist.items()},
            "stats": self.stats(),
            "events": self.events[-60:],
            "incidents": self.incidents.recent(25),
            "zones": {z: {q: round(v, 2) for q, v in vals.items()} for z, vals in self.consensus.zone_values.items()},
            "server_time": round(clock.now(), 2),
            "config": self.cfg.as_dict(),
        }
