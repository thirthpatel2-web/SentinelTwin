"""
recovery.py
-----------
The self-healing engine. Once diagnosis.py (or the fast-path in
security.py) has confirmed a root cause, this module decides and
executes a recovery action, then verifies whether it actually worked -
closing the
Monitor -> Predict/Detect -> Security Layer -> Diagnose -> Respond -> Recover -> Verify
loop that is the core idea of SentinelTwin.

Action selection is itself explainable and root-cause-driven:

  NETWORK_FAILURE      -> ISOLATE + REROUTE to a healthy backup device
                          (physical device may still be fine, so it is
                          re-checked, not permanently retired)
  HARDWARE_FAULT       -> ISOLATE + ACTIVATE_BACKUP (device presumed
                          faulty until a technician swaps it)
  SENSOR_DRIFT         -> RECALIBRATE (soft-reset the rolling baseline)
                          rather than isolating - it's still producing
                          usable-ish data, just biased
  MALICIOUS_TAMPERING,
  DOS_FLOOD_ATTACK,
  IDENTITY_SPOOFING    -> already firewalled by security.py before this
                          runs; ISOLATE + quarantine here, and hold
                          reactivation until the firewall block itself
                          expires (not just the internal verify window)
  UNCLASSIFIED_ANOMALY -> ISOLATE cautiously and keep observing

Verification: after VERIFY_AFTER_TICKS ticks of watching a reactivated /
recalibrated device, if its anomaly score has stayed low the whole
window it is marked RECOVERED; otherwise recovery is retried / escalated.
Devices blocked by the firewall additionally can't even START that
verification window until the block itself has expired.
"""

from __future__ import annotations
from typing import Optional

from digital_twin import DeviceTwin, DeviceState, DigitalTwinRegistry
from simulator import NetworkSimulator, FaultMode
from security import Firewall

VERIFY_AFTER_TICKS = 4
SECURITY_CAUSES = ("MALICIOUS_TAMPERING", "DOS_FLOOD_ATTACK", "IDENTITY_SPOOFING")


def _mark(twin: DeviceTwin, msg: str) -> None:
    twin.recovery_log.append(f"[RECOVERY] {msg}")


def handle_anomalous(twin: DeviceTwin, registry: DigitalTwinRegistry, sim: NetworkSimulator) -> None:
    if twin.state != DeviceState.ANOMALOUS:
        return

    cause = twin.root_cause
    sim_dev = sim.get(twin.device_id)

    if cause == "SENSOR_DRIFT":
        # soft fix: recalibrate in place, no isolation needed
        twin.history.clear()
        twin.baseline_mean.clear()
        twin.baseline_std.clear()
        if sim_dev:
            sim_dev.clear_fault()
        twin.state = DeviceState.RECOVERING
        twin._verify_counter = 0  # type: ignore[attr-defined]
        _mark(twin, "RECALIBRATE issued — rolling baseline reset, monitoring for stability.")
        return

    # everything else: isolate first
    twin.state = DeviceState.ISOLATED
    _mark(twin, f"Device ISOLATED (root cause: {cause}, trust={twin.trust_score:.2f}).")

    if cause == "NETWORK_FAILURE":
        backup = registry.find_backup_for(twin.device_id)
        if backup:
            twin.rerouted_to = backup.device_id
            backup.state = DeviceState.NORMAL
            _mark(twin, f"Traffic REROUTED to standby device {backup.device_id} in {backup.zone}.")
        else:
            _mark(twin, "No standby device available in zone for reroute — flagged for manual reroute.")
        _begin_reactivation(twin, sim)

    elif cause == "HARDWARE_FAULT":
        backup = registry.find_backup_for(twin.device_id)
        if backup:
            backup.state = DeviceState.NORMAL
            backup.backup_for = twin.device_id
            twin.rerouted_to = backup.device_id
            _mark(twin, f"Standby device {backup.device_id} ACTIVATED to cover for faulty hardware.")
        else:
            _mark(twin, "No standby device available — service degraded until physical replacement.")
        _begin_reactivation(twin, sim)

    elif cause in SECURITY_CAUSES:
        twin.firewall_blocked = True
        _mark(twin, f"Device QUARANTINED by the security layer ({cause}) — no reroute of its data, held until firewall block expires.")
        # security-flagged devices need a longer, stricter re-check before trust is restored
        _begin_reactivation(twin, sim, strict=True)

    else:  # UNCLASSIFIED_ANOMALY
        _mark(twin, "Isolated cautiously pending further observation.")
        _begin_reactivation(twin, sim)


def _begin_reactivation(twin: DeviceTwin, sim: NetworkSimulator, strict: bool = False) -> None:
    sim_dev = sim.get(twin.device_id)
    if sim_dev:
        sim_dev.clear_fault()
    twin.history.clear()
    twin.baseline_mean.clear()
    twin.baseline_std.clear()
    twin.state = DeviceState.RECOVERING
    twin._verify_counter = 0  # type: ignore[attr-defined]
    twin._verify_strict = strict  # type: ignore[attr-defined]


def progress_recovery(twin: DeviceTwin, firewall: Optional[Firewall] = None) -> None:
    """Called every tick for devices in RECOVERING to check verification progress."""
    if twin.state != DeviceState.RECOVERING:
        return

    # a firewalled device can't even start its clean-tick countdown until
    # the block itself has expired - the security layer's decision holds
    # priority over the ordinary recovery verification loop
    if twin.firewall_blocked and firewall is not None:
        if firewall.is_blocked(twin.device_id):
            return
        twin.firewall_blocked = False
        twin.firewall_reason = None

    from anomaly_detector import score_device  # local import avoids circular import at module load

    counter = getattr(twin, "_verify_counter", 0) + 1
    twin._verify_counter = counter  # type: ignore[attr-defined]
    strict = getattr(twin, "_verify_strict", False)
    needed = (VERIFY_AFTER_TICKS + 2) if strict else VERIFY_AFTER_TICKS

    if len(twin.history) < 3:
        return  # not enough fresh data yet to judge

    score, _, _ = score_device(twin)
    if score >= 0.4:
        # still unstable - reset the verification clock
        twin._verify_counter = 0  # type: ignore[attr-defined]
        _mark(twin, f"Verification check failed (score {score:.2f}) — restarting observation window.")
        return

    if counter >= needed:
        twin.state = DeviceState.RECOVERED
        twin.root_cause = None
        twin.root_cause_confidence = 0.0
        _mark(twin, f"VERIFIED healthy after {counter} clean ticks — device RECOVERED.")
