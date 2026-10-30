"""
End-to-end behaviour tests: each one injects a ground-truth fault into a
seeded simulated network and checks what the closed loop did. These pin
the behaviours the paper claims, so a regression shows up as a failing
test rather than a silently worse table.

    python -m pytest -q
"""

import sys
from dataclasses import replace
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import clock                                    # noqa: E402
from config import PipelineConfig               # noqa: E402
from engine import SentinelEngine               # noqa: E402
from mqtt_bridge import sign, to_message        # noqa: E402
from security import Firewall, RateTracker      # noqa: E402


def run(fault=None, target=None, ticks=200, cfg=None, seed=1, zone_event=None, **params):
    clock.use(clock.SimClock(1000.0))
    e = SentinelEngine(cfg=cfg or PipelineConfig(), seed=seed)
    for _ in range(60):
        e.tick()
    if fault:
        e.inject(target, fault, **params)
    if zone_event:
        e.zone_event(zone_event, magnitude_t=6.0)
    for _ in range(ticks):
        e.tick()
    return e


def incidents_on(e, device_id):
    return [i for i in e.incidents.all() if i.device_id == device_id]


@pytest.mark.parametrize("fault,target,cause", [
    ("HARDWARE", "TEMP-001", "HARDWARE_FAULT"),
    ("STUCK", "HUMI-006", "HARDWARE_FAULT"),
    ("DROPOUT", "MOTI-007", "HARDWARE_FAULT"),
    ("NETWORK", "TEMP-005", "NETWORK_FAILURE"),
    ("DRIFT", "HUMI-002", "SENSOR_DRIFT"),
    ("TAMPER", "MOTI-003", "MALICIOUS_TAMPERING"),
    ("FLOOD", "TEMP-009", "DOS_FLOOD_ATTACK"),
    ("SPOOF", "HUMI-010", "IDENTITY_SPOOFING"),
    ("GATEWAY", "GATE-004", "GATEWAY_FAILURE"),
])
def test_each_fault_is_diagnosed_and_verified(fault, target, cause):
    e = run(fault, target)
    incs = incidents_on(e, target)
    assert incs, f"{fault} was never detected"
    assert incs[0].cause == cause
    assert incs[0].outcome == "RECOVERED"
    assert incs[0].t_verified is not None and incs[0].t_verified > incs[0].t_detect


def test_fault_free_network_stays_quiet():
    e = run(ticks=400)
    assert len(e.incidents.all()) <= 1


def test_gateway_failure_does_not_isolate_its_children():
    e = run("GATEWAY", "GATE-004")
    children = {"TEMP-001", "HUMI-002", "MOTI-003"}
    isolations = [a for i in e.incidents.all() if i.device_id in children for a in i.actions
                  if a["action"] in ("ACTIVATE_BACKUP", "QUARANTINE")]
    assert not isolations


def test_heatwave_is_not_a_fault_with_consensus():
    e = run(zone_event="Zone-A")
    zone_a = {d.device_id for d in e.registry.in_zone("Zone-A") if "MOTI" not in d.device_id}
    assert not [i for i in e.incidents.all() if i.device_id in zone_a]
    assert any("ENVIRONMENT CHANGE" in ev["message"] for ev in e.events)


def test_fabricated_ramp_is_recognised_as_an_attack():
    e = run("TAMPER_RAMP", "TEMP-005", attacker="fabricate", slope=0.25)
    incs = incidents_on(e, "TEMP-005")
    assert incs and incs[0].cause == "STEALTHY_TAMPERING"
    assert any(a["action"] == "QUARANTINE" for a in incs[0].actions)


def test_compromised_slow_ramp_is_caught_by_failed_verification():
    """Often indistinguishable from drift at first; whatever the first verdict, the attack must end quarantined."""
    for seed in (2, 3, 4):
        e = run("TAMPER_RAMP", "TEMP-001", attacker="compromised", slope=0.15, seed=seed)
        actions = [a["action"] for i in incidents_on(e, "TEMP-001") for a in i.actions]
        assert "QUARANTINE" in actions, (seed, actions)


def test_mac_drops_rogue_publisher_before_it_reaches_the_twin():
    e = run("TAMPER_RAMP", "TEMP-001", cfg=replace(PipelineConfig(), use_auth=True), attacker="rogue", slope=0.6, seed=2)
    assert not incidents_on(e, "TEMP-001")
    assert e.ingestor.dropped > 0


def test_scoped_quarantine_keeps_genuine_device_online():
    e = run("SPOOF", "HUMI-010")
    twin = e.registry.get("HUMI-010")
    assert not twin.firewall_blocked
    assert any("|" in h["key"] for h in e.firewall.history)


def test_firewall_escalates_and_permanent_mode():
    clock.use(clock.SimClock(0.0))
    fw = Firewall()
    assert [fw.block("x", "r") for _ in range(4)] == [30, 60, 120, 240]
    assert Firewall(permanent=True).block("y", "r") == float("inf")


def test_rate_tracker_learns_cadence_and_flags_flood():
    rt = RateTracker()
    t = 0.0
    for _ in range(20):
        t += 1.5
        assert not rt.record("d", t)
    flagged = [rt.record("d", t + i * 0.03) for i in range(40)]
    assert any(flagged)


def test_hmac_round_trip_and_tamper_detection():
    key = bytes(range(32))
    raw = sign(b'{"seq":1,"pub":"X-fw","temperature":24.10}', key)
    assert to_message("sentineltwin/X/telemetry", raw, {"X": key}).auth_ok is True
    assert to_message("sentineltwin/X/telemetry", raw.replace(b"24.10", b"29.10"), {"X": key}).auth_ok is False
    assert to_message("sentineltwin/X/telemetry", raw, {}).auth_ok is None


def test_runs_are_reproducible():
    a = [(i.device_id, i.cause, i.t_detect) for i in run("DRIFT", "HUMI-002", seed=5).incidents.all()]
    b = [(i.device_id, i.cause, i.t_detect) for i in run("DRIFT", "HUMI-002", seed=5).incidents.all()]
    assert a == b
