"""
recovery.py
-----------
The self-healing engine: executes the action response.py chose, then
VERIFIES it worked before declaring the device recovered - closing

    Monitor -> Detect -> Security Layer -> Diagnose -> Respond -> Recover -> Verify

Actions
  OBSERVE           no intervention (e.g. a symptom of an upstream gateway failure)
  RECALIBRATE       re-learn the device's baseline in place; device stays online
  ACTIVATE_BACKUP   isolate the device, hand its role to a standby, open a repair ticket
  REROUTE           keep the device, carry its service on a standby path until the link heals
  GATEWAY_FAILOVER  re-home a failed gateway's children onto a healthy gateway
  QUARANTINE        firewall (device- or publisher-scoped), rotate credentials
  DISTRUST_DATA     keep the device online but stop trusting its data; standby covers;
                    keep collecting evidence and act once the diagnosis sharpens

Verification (post-action, closed loop)
  A device counts a clean reading only if its anomaly score is low, its
  residual against the zone is back within its last VERIFIED offset (so
  re-learning cannot launder an attacker's offset), its link is healthy
  and no provenance anomalies occurred. A firewalled device cannot even
  start counting until the block expires. Repeated failures mean the
  action did not fix the real cause: the action is marked failed, the
  device is re-diagnosed on fresh evidence, and the next-best action is
  taken (escalation). After MAX_ESCALATIONS the incident goes to a human.

With verification disabled (an ablation), every action is assumed to
work immediately - which is how many self-healing systems are evaluated,
and what the evaluation's "false recovery" metric exposes.
"""

from __future__ import annotations
from typing import Callable, Dict, List, Optional

import clock
from config import PipelineConfig
from digital_twin import DeviceTwin, DeviceState, DigitalTwinRegistry
from incidents import IncidentLog
from security import Firewall, publisher_key
import diagnosis
import response
import trust

VERIFY_TICKS = 4
VERIFY_TICKS_STRICT = 6
VERIFY_GRACE_TICKS = 3
VERIFY_FAILURE_LIMIT = 6
MAX_ESCALATIONS = 3
REPAIR_SECONDS = 40 * 1.5
CONTAIN_DECIDE_PROBABILITY = 0.8
CONTAIN_MAX_TICKS = 25
SECURITY_CAUSES = trust.ATTACK_CAUSES

LogFn = Callable[[str, str, str], None]


class RecoveryEngine:
    def __init__(self, registry: DigitalTwinRegistry, firewall: Firewall, incidents: IncidentLog,
                 cfg: PipelineConfig, log_event: LogFn, sim=None, ground_truth: Optional[Callable] = None) -> None:
        self.registry = registry
        self.firewall = firewall
        self.incidents = incidents
        self.cfg = cfg
        self.log = log_event
        self.sim = sim
        self.ground_truth = ground_truth or (lambda device_id: None)
        self.rehomed: Dict[str, List[str]] = {}
        self.foreign_publisher: Dict[str, str] = {}

    # ---- helpers ---------------------------------------------------------
    def _mark(self, twin: DeviceTwin, msg: str) -> None:
        twin.recovery_log.append(f"[RECOVERY] {msg}")

    def _sim_apply(self, twin: DeviceTwin, action: str) -> None:
        if self.sim is not None:
            dev = self.sim.get(twin.device_id)
            if dev is not None:
                dev.apply_action(action)

    def _release_backup(self, twin: DeviceTwin) -> None:
        if twin.rerouted_to:
            b = self.registry.get(twin.rerouted_to)
            if b and b.backup_for == twin.device_id:
                b.backup_for = None
        twin.rerouted_to = None

    def _cover_with_backup(self, twin: DeviceTwin) -> Optional[DeviceTwin]:
        b = self.registry.find_backup_for(twin.device_id)
        if b:
            b.backup_for = twin.device_id
            twin.rerouted_to = b.device_id
        return b

    def _start_verification(self, twin: DeviceTwin, strict: bool = False) -> None:
        twin.state = DeviceState.RECOVERING
        twin.verify_counter = 0
        twin.verify_failures = 0
        twin.verify_needed = VERIFY_TICKS_STRICT if strict else VERIFY_TICKS
        twin.contained_ticks = 0
        if not self.cfg.verify:
            self._close(twin, "UNVERIFIED_CLOSE", "assumed fixed (verification disabled)")

    # ---- entry point: a confirmed diagnosis ------------------------------
    def handle_anomalous(self, twin: DeviceTwin) -> None:
        if twin.state != DeviceState.ANOMALOUS:
            return
        inc = self.incidents.get(twin.incident_id)
        if inc is None or inc.outcome != "OPEN":
            gt = self.ground_truth(twin.device_id)
            inc = self.incidents.open(
                device_id=twin.device_id, zone=twin.zone, device_type=twin.device_type, is_real=twin.is_real,
                t_detect=twin.suspect_since or clock.now(), t_diagnose=clock.now(),
                cause=twin.root_cause or "UNCLASSIFIED_ANOMALY", confidence=twin.root_cause_confidence,
                posterior=dict(twin.posterior), explanation=list(twin.explanation), evidence=dict(twin.evidence),
                gt_mode=gt[0] if gt else "NONE", gt_expected=gt[1] if gt else "NONE",
                gt_onset=gt[2] if gt else None, gt_attack=gt[3] if gt else False)
            twin.incident_id = inc.id
            twin.failed_actions = []
            twin.escalation_level = 0
            if twin.root_cause in SECURITY_CAUSES:
                trust.note_confirmed_attack(twin, self.cfg.trust_model)
        self._act(twin, exclude=twin.failed_actions)

    def _act(self, twin: DeviceTwin, exclude: Optional[List[str]] = None) -> None:
        action, costs, reason = response.choose_action(twin, self.registry, self.cfg, exclude)
        inc = self.incidents.get(twin.incident_id)
        if inc:
            inc.actions.append({"t": clock.now(), "action": action, "cause": twin.root_cause,
                                "expected_cost": costs.get(action), "reason": reason})
            if inc.t_contain is None:
                inc.t_contain = clock.now()
        twin.current_action = action
        self._mark(twin, f"{action} chosen for {twin.root_cause} - {reason}.")
        getattr(self, f"_do_{action.lower()}")(twin)

    # ---- actions ---------------------------------------------------------
    def _do_observe(self, twin: DeviceTwin) -> None:
        self._mark(twin, "No intervention - waiting for the underlying cause to clear.")
        self._start_verification(twin)

    def _do_recalibrate(self, twin: DeviceTwin) -> None:
        self._sim_apply(twin, "RECALIBRATE")
        twin.reset_learning()
        self._mark(twin, "RECALIBRATE issued - baseline re-learned in place; checking against last verified offset.")
        self._start_verification(twin)

    def _do_activate_backup(self, twin: DeviceTwin) -> None:
        b = self._cover_with_backup(twin)
        twin.state = DeviceState.ISOLATED
        twin.repair_eta = clock.now() + REPAIR_SECONDS
        self._sim_apply(twin, "ACTIVATE_BACKUP")
        self._mark(twin, (f"Device ISOLATED; standby {b.device_id} ACTIVATED" if b else
                          "Device ISOLATED; no standby available - service degraded") + "; repair ticket opened.")
        if not self.cfg.verify:
            twin.repair_eta = None
            twin.reset_learning()
            self._start_verification(twin)

    def _do_reroute(self, twin: DeviceTwin) -> None:
        b = self._cover_with_backup(twin)
        self._mark(twin, f"Traffic REROUTED to standby {b.device_id}." if b else
                   "No standby path - flagged for manual reroute.")
        twin.reset_learning()
        self._start_verification(twin)

    def _do_gateway_failover(self, twin: DeviceTwin) -> None:
        target = self.registry.find_failover_gateway(twin.device_id)
        children = [d for d in self.registry.all() if d.gateway_id == twin.device_id]
        if target:
            for d in children:
                d.gateway_id = target.device_id
            self.rehomed[twin.device_id] = [d.device_id for d in children]
        twin.state = DeviceState.ISOLATED
        twin.repair_eta = clock.now() + REPAIR_SECONDS
        self._sim_apply(twin, "GATEWAY_FAILOVER")
        self._mark(twin, f"{len(children)} child devices re-homed to gateway {target.device_id}; repair ticket opened."
                   if target else "No healthy gateway to fail over to - zone degraded.")
        self.log("RECOVERY", twin.device_id, f"Gateway failover: {len(children)} devices re-homed"
                 + (f" to {target.device_id}." if target else " - none available."))
        if not self.cfg.verify:
            twin.repair_eta = None
            self._start_verification(twin)

    def _do_quarantine(self, twin: DeviceTwin) -> None:
        cause = twin.root_cause or "MALICIOUS_TAMPERING"
        rogue = self.foreign_publisher.get(twin.device_id)
        if self.cfg.scoped_quarantine and rogue and cause in ("IDENTITY_SPOOFING", "STEALTHY_TAMPERING"):
            key = publisher_key(twin.device_id, rogue)
            scope = f"publisher '{rogue}' only - the genuine device keeps reporting"
        else:
            key = twin.device_id
            scope = "whole device"
            twin.firewall_blocked = True
            twin.firewall_reason = cause
        if not self.firewall.is_blocked(key):
            duration = self.firewall.block(key, cause)
            self.log("FIREWALL", twin.device_id, f"Quarantined ({scope}) for "
                     f"{'ever' if duration == float('inf') else f'{int(duration)}s'}: {cause}.")
        self._sim_apply(twin, "QUARANTINE")
        self._mark(twin, f"QUARANTINED ({scope}); credentials rotated; strict re-verification after the block.")
        if key == twin.device_id:
            self._cover_with_backup(twin)
        self._start_verification(twin, strict=True)

    def _do_distrust_data(self, twin: DeviceTwin) -> None:
        twin.state = DeviceState.CONTAINED
        twin.data_trusted = False
        twin.contained_ticks = 0
        b = self._cover_with_backup(twin)
        self._mark(twin, "CONTAINED - data distrusted (excluded from consensus and consumers)"
                   + (f", standby {b.device_id} covering" if b else "") + "; gathering more evidence.")

    # ---- per-tick progress ------------------------------------------------
    def progress(self, twin: DeviceTwin, fresh: bool) -> None:
        if twin.state == DeviceState.ISOLATED and twin.repair_eta is not None:
            if clock.now() >= twin.repair_eta:
                twin.repair_eta = None
                twin.reset_learning()
                self._mark(twin, "Repair ticket closed - device back online, verifying.")
                self._start_verification(twin)
            return
        if twin.state == DeviceState.CONTAINED:
            self._progress_contained(twin)
            return
        if twin.state != DeviceState.RECOVERING:
            return
        if twin.firewall_blocked:
            if self.firewall.is_blocked(twin.device_id):
                return
            twin.firewall_blocked = False
            twin.firewall_reason = None
        if not fresh:
            return
        twin.verify_counter += 1
        if twin.verify_counter <= VERIFY_GRACE_TICKS or len(twin.history) < 3:
            return
        if self._clean(twin):
            if twin.verify_counter - VERIFY_GRACE_TICKS >= twin.verify_needed:
                self._close(twin, "RECOVERED", f"VERIFIED healthy after {twin.verify_counter - VERIFY_GRACE_TICKS} clean readings")
            return
        twin.verify_failures += 1
        twin.verify_counter = VERIFY_GRACE_TICKS     # restart the clean-reading count
        inc = self.incidents.get(twin.incident_id)
        if inc:
            inc.verify_failures += 1
        if twin.verify_failures >= VERIFY_FAILURE_LIMIT:
            self._escalate(twin)

    def _clean(self, twin: DeviceTwin) -> bool:
        if twin.last_anomaly_score >= 0.4:
            return False
        latest = twin.latest().values
        if latest.get("signal_strength", 100) < 70 or latest.get("packet_loss", 0) >= 10:
            return False
        if twin.residuals:
            for metric, r in twin.residuals[-1].items():
                if metric in twin.ref_offset:
                    mean, sd = twin.ref_offset[metric]
                    if abs(r - mean) / sd >= 3.5:
                        return False
        if any(clock.now() - t <= 6.0 for t in twin.provenance_events):
            return False
        return True

    def _progress_contained(self, twin: DeviceTwin) -> None:
        twin.contained_ticks += 1
        diagnosis.diagnose(twin, self.registry, self.cfg, force=True)
        top = max(twin.posterior.values()) if twin.posterior else 0.0
        if top >= CONTAIN_DECIDE_PROBABILITY or twin.contained_ticks >= CONTAIN_MAX_TICKS:
            twin.data_trusted = True
            self._release_backup(twin)
            twin.state = DeviceState.ANOMALOUS
            self._mark(twin, f"Evidence sharpened after {twin.contained_ticks} readings: "
                       f"{twin.root_cause} ({top:.0%}).")
            self._act(twin, exclude=list(set(twin.failed_actions + ["DISTRUST_DATA", "OBSERVE"])))

    def _escalate(self, twin: DeviceTwin) -> None:
        failed = twin.current_action or "UNKNOWN"
        twin.failed_actions.append(failed)
        twin.escalation_level += 1
        inc = self.incidents.get(twin.incident_id)
        if inc:
            inc.escalations += 1
        self._release_backup(twin)
        self.log("RECOVERY", twin.device_id, f"Verification failed {twin.verify_failures}x after {failed} - escalating.")
        if twin.escalation_level > MAX_ESCALATIONS:
            twin.state = DeviceState.ISOLATED
            twin.repair_eta = None
            self._cover_with_backup(twin)
            self._close(twin, "MANUAL", "automatic recovery exhausted - handed to an operator")
            return
        diagnosis.diagnose(twin, self.registry, self.cfg, force=True)
        twin.state = DeviceState.ANOMALOUS
        self._act(twin, exclude=twin.failed_actions)

    def _close(self, twin: DeviceTwin, outcome: str, msg: str) -> None:
        inc = self.incidents.get(twin.incident_id)
        if inc and inc.outcome == "OPEN":
            inc.outcome = outcome
            inc.t_verified = clock.now()
            inc.gt_active_at_close = self.ground_truth(twin.device_id) is not None
        if outcome != "MANUAL":
            twin.state = DeviceState.RECOVERED
            twin.data_trusted = True
            self._release_backup(twin)
            twin.root_cause = None
            twin.root_cause_confidence = 0.0
            twin.current_action = None
            twin.failed_actions = []
            twin.escalation_level = 0
            twin.incident_id = None
            twin.suspect_since = None
            if twin.device_type == "gateway" and twin.device_id in self.rehomed:
                for child_id in self.rehomed.pop(twin.device_id):
                    child = self.registry.get(child_id)
                    if child:
                        child.gateway_id = twin.device_id
        self._mark(twin, f"{msg} - incident {outcome}.")
        self.log("VERIFIED" if outcome == "RECOVERED" else "RECOVERY", twin.device_id, f"{msg}.")
