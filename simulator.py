"""
simulator.py
------------
A physically-grounded IoT testbed simulator with ground truth.

Three things make this different from "random numbers with spikes":

1. Shared physics per zone. Every zone has one environment process
   (temperature + humidity with a diurnal cycle, a mean-reverting random
   walk, and optional zone-wide events such as a heatwave). Every sensor
   in the zone MEASURES that same environment plus its own noise, so
   co-located devices are physically redundant - exactly the property a
   digital twin can exploit to tell "the sensor is wrong" from "the room
   changed". The environment can also be replayed from real recorded
   traces (see datasets/intel_lab.py) instead of being synthetic.

2. Faults and attacks are injected at the right layer, with an explicit
   threat model, and emitted as real messages (sequence number,
   timestamp, publisher fingerprint, authentication result) that go
   through the same ingest path as real MQTT hardware:

     benign   HARDWARE (spike), STUCK, DROPOUT, NETWORK, GATEWAY, DRIFT
     attacks  TAMPER (abrupt multi-metric injection), TAMPER_RAMP (slow,
              drift-shaped false-data injection), ON_OFF (intermittent
              attacker gaming trust), FLOOD (DoS), SPOOF (identity)

   TAMPER_RAMP takes an attacker model, because what is detectable
   depends on what the attacker can do:
     fabricate    replaces readings in-path with plausible synthetic
                  values (does not see the true physical signal)
     inpath       modifies the TRUE reading in-path (+ ramp); without the
                  device key it cannot produce a valid MAC
     rogue        a second publisher injects ramped readings under the
                  victim's device_id (sequence/publisher conflicts)
     compromised  the device firmware itself adds the ramp: valid MAC,
                  valid sequence, tracks the physics - telemetry-wise
                  identical to drift except for its rate

3. Ground truth and realistic action efficacy. Every injection is
   recorded with its onset time. Recovery actions are applied through
   apply_action(), which only fixes the fault if that action would fix it
   in reality (recalibration does not stop an attacker; quarantine does
   not repair a drifting sensor). So a wrong diagnosis leads to a failed
   verification, which the closed loop has to notice - and the
   evaluation can measure that honestly.
"""

from __future__ import annotations
import math
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

import clock
from digital_twin import DeviceTwin, DigitalTwinRegistry, DeviceState, ENV_METRICS, QUANTITY_OF

TICK_SECONDS = 1.5
REPAIR_DELAY_TICKS = 40          # technician swap / reflash after a maintenance ticket
NETWORK_FAULT_TICKS = 30         # a link outage heals by itself after this long
FLOOD_MSGS_PER_TICK = 40


class FaultMode(str, Enum):
    NONE = "NONE"
    HARDWARE = "HARDWARE"
    STUCK = "STUCK"
    DROPOUT = "DROPOUT"
    NETWORK = "NETWORK"
    GATEWAY = "GATEWAY"
    DRIFT = "DRIFT"
    TAMPER = "TAMPER"
    MALICIOUS = "MALICIOUS"       # backwards-compatible alias of TAMPER
    TAMPER_RAMP = "TAMPER_RAMP"
    ON_OFF = "ON_OFF"
    FLOOD = "FLOOD"
    SPOOF = "SPOOF"


# The diagnosis a perfect system would give for each injected mode.
EXPECTED_CAUSE = {
    FaultMode.HARDWARE: "HARDWARE_FAULT",
    FaultMode.STUCK: "HARDWARE_FAULT",
    FaultMode.DROPOUT: "HARDWARE_FAULT",
    FaultMode.NETWORK: "NETWORK_FAILURE",
    FaultMode.GATEWAY: "GATEWAY_FAILURE",
    FaultMode.DRIFT: "SENSOR_DRIFT",
    FaultMode.TAMPER: "MALICIOUS_TAMPERING",
    FaultMode.MALICIOUS: "MALICIOUS_TAMPERING",
    FaultMode.TAMPER_RAMP: "STEALTHY_TAMPERING",
    FaultMode.ON_OFF: "MALICIOUS_TAMPERING",
    FaultMode.FLOOD: "DOS_FLOOD_ATTACK",
    FaultMode.SPOOF: "IDENTITY_SPOOFING",
}
ATTACK_MODES = {FaultMode.TAMPER, FaultMode.MALICIOUS, FaultMode.TAMPER_RAMP,
                FaultMode.ON_OFF, FaultMode.FLOOD, FaultMode.SPOOF}

# blueprint: metric -> (baseline, noise). Quantity metrics (temperature,
# humidity...) are NOT drawn from the baseline - they measure the zone
# environment; the baseline is only used for non-physical metrics.
DEVICE_BLUEPRINT = {
    "temp_sensor": {
        "temperature": (24.0, 0.25), "humidity_ambient": (40.0, 0.6),
        "battery": (90.0, 0.3), "signal_strength": (85.0, 2.0),
    },
    "humidity_sensor": {
        "humidity": (40.0, 0.6), "temperature_ambient": (24.0, 0.25),
        "battery": (88.0, 0.3), "signal_strength": (82.0, 2.0),
    },
    "motion_sensor": {
        "motion_events": (2.0, 0.3), "vibration_level": (0.5, 0.15),
        "battery": (75.0, 0.3), "signal_strength": (80.0, 2.0),
    },
    "gateway": {
        "throughput_mbps": (120.0, 4.0), "cpu_load_pct": (35.0, 3.0),
        "battery": (100.0, 0.0), "signal_strength": (95.0, 1.0),
    },
}


@dataclass
class Message:
    """One telemetry message, exactly as the ingest layer sees it."""
    device_id: str
    payload: Dict[str, object]
    seq: Optional[int]
    ts: float
    publisher_id: Optional[str] = None
    auth_ok: Optional[bool] = None      # None = authentication not in use


@dataclass
class GroundTruth:
    mode: FaultMode
    onset: float
    params: Dict[str, object] = field(default_factory=dict)

    @property
    def expected_cause(self) -> str:
        return EXPECTED_CAUSE.get(self.mode, "NONE")

    @property
    def is_attack(self) -> bool:
        return self.mode in ATTACK_MODES


class ZoneEnvironment:
    """Temperature/humidity a zone's sensors all physically measure."""

    def __init__(self, zone: str, rng: random.Random, base_t: float = 24.0, base_h: float = 40.0,
                 diurnal_amp: float = 1.2, diurnal_period_ticks: int = 480,
                 trace: Optional[List[tuple]] = None) -> None:
        self.zone = zone
        self.rng = rng
        self.base_t, self.base_h = base_t, base_h
        self.amp, self.period = diurnal_amp, diurnal_period_ticks
        self.phase = rng.uniform(0, 2 * math.pi)
        self.rw_t = 0.0
        self.rw_h = 0.0
        self.tick_n = 0
        self.trace = trace           # optional list of (T, H) replayed from real data
        self.event: Optional[dict] = None
        self.T, self.H = base_t, base_h

    def start_event(self, magnitude_t: float = 5.0, ramp_ticks: int = 15, hold_ticks: int = 60) -> None:
        """A real, zone-wide physical change (e.g. heatwave / HVAC failure). Not a fault."""
        self.event = {"mag": magnitude_t, "ramp": ramp_ticks, "hold": hold_ticks, "age": 0}

    def event_offset(self) -> float:
        if not self.event:
            return 0.0
        e = self.event
        e["age"] += 1
        a, r, h = e["age"], e["ramp"], e["hold"]
        if a <= r:
            return e["mag"] * a / r
        if a <= r + h:
            return e["mag"]
        if a <= 2 * r + h:
            return e["mag"] * (2 * r + h - a) / r
        self.event = None
        return 0.0

    def step(self) -> None:
        self.tick_n += 1
        off = self.event_offset()
        if self.trace:
            t, h = self.trace[self.tick_n % len(self.trace)]
            self.T, self.H = t + off, h - 1.5 * off
            return
        # mean-reverting random walk (Ornstein-Uhlenbeck) + diurnal cycle
        self.rw_t += -0.05 * self.rw_t + self.rng.gauss(0, 0.12)
        self.rw_h += -0.05 * self.rw_h + self.rng.gauss(0, 0.30)
        diurnal = self.amp * math.sin(2 * math.pi * self.tick_n / self.period + self.phase)
        self.T = self.base_t + diurnal + self.rw_t + off
        # relative humidity falls as temperature rises (roughly -1.5 %RH per degC)
        self.H = self.base_h - 1.5 * (diurnal + off) + self.rw_h


class SimulatedDevice:
    def __init__(self, twin: DeviceTwin, rng: random.Random):
        self.twin = twin
        self.rng = rng
        self.seq = rng.randint(0, 1000)
        self.publisher_id = f"{twin.device_id}-fw"
        self.sent_identity = False
        self.mode = FaultMode.NONE
        self.params: Dict[str, object] = {}
        self.fault_ticks = 0
        self.gt: Optional[GroundTruth] = None
        self.repair_in: Optional[int] = None     # ticks until a technician fix lands
        self.offset = 0.0
        self.packet_loss = 0.0
        self.stuck_value: Optional[float] = None
        self.target_metric: Optional[str] = None
        self.rogue_seq = rng.randint(5000, 9000)
        self.frozen: Dict[str, float] = {}

    # ---- fault lifecycle -------------------------------------------------
    def inject_fault(self, mode: FaultMode, **params) -> None:
        if mode == FaultMode.MALICIOUS:
            mode = FaultMode.TAMPER
        self.mode = mode
        self.params = dict(params)
        self.fault_ticks = 0
        self.offset = 0.0
        self.packet_loss = 0.0
        self.stuck_value = None
        self.repair_in = None
        quantity_metrics = [m for m in DEVICE_BLUEPRINT[self.twin.device_type] if m not in ENV_METRICS]
        primary = quantity_metrics[0]
        self.target_metric = params.get("metric") or (
            primary if mode in (FaultMode.DRIFT, FaultMode.TAMPER_RAMP, FaultMode.STUCK)
            else self.rng.choice(quantity_metrics))
        self.gt = GroundTruth(mode=mode, onset=clock.now(), params=dict(params))

    def clear_fault(self) -> None:
        self.mode = FaultMode.NONE
        self.params = {}
        self.fault_ticks = 0
        self.offset = 0.0
        self.packet_loss = 0.0
        self.stuck_value = None
        self.repair_in = None
        self.gt = None

    def apply_action(self, action: str) -> None:
        """Apply a recovery action to the PHYSICAL device - only fixes what it would really fix."""
        m = self.mode
        if m == FaultMode.NONE:
            return
        attacker = self.params.get("attacker", "fabricate")
        if action == "RECALIBRATE" and m == FaultMode.DRIFT:
            self.clear_fault()
        elif action in ("ACTIVATE_BACKUP", "REPAIR") and m in (
                FaultMode.HARDWARE, FaultMode.STUCK, FaultMode.DROPOUT, FaultMode.DRIFT, FaultMode.GATEWAY):
            self.repair_in = REPAIR_DELAY_TICKS
        elif action == "GATEWAY_FAILOVER" and m == FaultMode.GATEWAY:
            self.repair_in = REPAIR_DELAY_TICKS
        elif action == "QUARANTINE" and m in ATTACK_MODES:
            if self.params.get("persistent"):
                return                                  # implanted firmware: survives credential rotation
            if m == FaultMode.TAMPER_RAMP and attacker == "compromised":
                self.repair_in = REPAIR_DELAY_TICKS     # needs a firmware reflash
            else:
                self.clear_fault()                      # credentials rotated, attacker locked out

    # ---- telemetry -------------------------------------------------------
    def _physical_values(self, env: ZoneEnvironment) -> Dict[str, float]:
        bp = DEVICE_BLUEPRINT[self.twin.device_type]
        values: Dict[str, float] = {}
        for metric, (base, noise) in bp.items():
            q = QUANTITY_OF.get(metric)
            true_val = env.T if q == "T" else env.H if q == "H" else base
            values[metric] = round(self.rng.gauss(true_val, noise), 2)
        values["packet_loss"] = 0.0
        return values

    def _gateway_down(self, gateways: Dict[str, "SimulatedDevice"]) -> bool:
        gw = gateways.get(self.twin.gateway_id or "")
        return bool(gw and gw is not self and gw.mode == FaultMode.GATEWAY)

    def _msg(self, values: Dict[str, float], auth_ok: Optional[bool], publisher: Optional[str] = None,
             seq: Optional[int] = None, ts: Optional[float] = None, identity: Optional[dict] = None) -> Message:
        payload: Dict[str, object] = dict(values)
        if identity is not None:
            payload.update(identity)
        elif not self.sent_identity:
            payload["device_type"] = self.twin.device_type
            payload["zone"] = self.twin.zone
            self.sent_identity = True
        if seq is None:
            self.seq += 1
            seq = self.seq
        return Message(self.twin.device_id, payload, seq, clock.now() if ts is None else ts,
                       publisher or self.publisher_id, auth_ok)

    def tick(self, env: ZoneEnvironment, gateways: Dict[str, "SimulatedDevice"], use_auth: bool) -> List[Message]:
        if self.repair_in is not None:
            self.repair_in -= 1
            if self.repair_in <= 0:
                self.clear_fault()
        self.fault_ticks += 1
        ok = True if use_auth else None
        bp = DEVICE_BLUEPRINT[self.twin.device_type]
        values = self._physical_values(env)
        m, p = self.mode, self.params
        out: List[Message] = []

        # upstream gateway outage degrades every child's link
        if self._gateway_down(gateways):
            values["signal_strength"] = round(max(0.0, self.rng.gauss(25, 8)), 2)
            values["packet_loss"] = round(self.rng.uniform(40, 80), 2)
            if self.rng.random() < 0.6:
                return []

        if m == FaultMode.HARDWARE:
            metric = self.target_metric
            spike = (1 if self.rng.random() < 0.5 else -1) * self.rng.uniform(35, 60)
            values[metric] = round(bp[metric][0] + spike, 2)
        elif m == FaultMode.STUCK:
            if self.stuck_value is None:
                self.stuck_value = values[self.target_metric]
            values[self.target_metric] = self.stuck_value
        elif m == FaultMode.DROPOUT:
            if self.rng.random() < float(p.get("drop_prob", 0.75)):
                return []
        elif m == FaultMode.NETWORK:
            values["signal_strength"] = max(0.0, round(bp["signal_strength"][0] - min(self.fault_ticks * 12, 90), 2))
            self.packet_loss = min(95.0, self.packet_loss + 15)
            values["packet_loss"] = round(self.packet_loss, 2)
            if self.fault_ticks > int(p.get("duration", NETWORK_FAULT_TICKS)):
                self.clear_fault()
            elif self.rng.random() < 0.6 * self.packet_loss / 100:
                return []
        elif m == FaultMode.GATEWAY:
            values["throughput_mbps"] = round(max(0.0, self.rng.gauss(4, 2)), 2)
            values["cpu_load_pct"] = round(min(100.0, self.rng.gauss(97, 1.5)), 2)
        elif m == FaultMode.DRIFT:
            noise = bp[self.target_metric][1]
            self.offset += float(p.get("rate", 0.25)) * noise
            values[self.target_metric] = round(values[self.target_metric] + self.offset, 2)
        elif m == FaultMode.TAMPER or (m == FaultMode.ON_OFF and self._on_phase()):
            for metric in bp:
                if metric in ENV_METRICS:
                    continue
                values[metric] = round(bp[metric][0] * self.rng.uniform(3.0, 5.0), 2)
            values["signal_strength"] = round(bp["signal_strength"][0] + self.rng.uniform(0, 1), 2)
        elif m == FaultMode.TAMPER_RAMP:
            out.extend(self._ramp_attack(values, bp, use_auth))
            if p.get("attacker", "fabricate") == "rogue":
                out.insert(0, self._msg(values, ok))     # the real device keeps publishing honestly
            return out
        elif m == FaultMode.FLOOD:
            base_ts = clock.now()
            for i in range(FLOOD_MSGS_PER_TICK):
                out.append(self._msg(dict(values), ok, ts=base_ts + i * TICK_SECONDS / FLOOD_MSGS_PER_TICK))
            return out
        elif m == FaultMode.SPOOF:
            out.append(self._msg(values, ok))
            fake_type = p.get("claimed_type") or next(t for t in DEVICE_BLUEPRINT if t != self.twin.device_type)
            self.rogue_seq += 1
            out.append(self._msg(self._physical_values(env), None if not use_auth else False,
                                 publisher="rogue-node", seq=self.rogue_seq,
                                 identity={"device_type": fake_type, "zone": p.get("claimed_zone", self.twin.zone)}))
            return out

        out.append(self._msg(values, ok))
        return out

    def _on_phase(self) -> bool:
        on, off = int(self.params.get("on_ticks", 4)), int(self.params.get("off_ticks", 26))
        return (self.fault_ticks % (on + off)) < on

    def _ramp_attack(self, values: Dict[str, float], bp: dict, use_auth: bool) -> List[Message]:
        p = self.params
        attacker = p.get("attacker", "fabricate")
        channels = int(p.get("channels", 1))
        targets = [m for m in bp if m not in ENV_METRICS][:channels] if channels > 1 else [self.target_metric]
        if not self.frozen:
            # the attacker learns typical values once, before ramping
            self.frozen = {m: values[m] for m in targets}
        self.offset += float(p.get("slope", 0.25)) * bp[targets[0]][1]
        forged = dict(values)
        for metric in targets:
            if attacker == "fabricate":
                # does not see the physical signal: plausible-looking noise around a learned value
                forged[metric] = round(self.rng.gauss(self.frozen[metric], bp[metric][1]) + self.offset, 2)
            else:
                forged[metric] = round(values[metric] + self.offset, 2)
        if attacker == "rogue":
            self.rogue_seq += 1
            return [self._msg(forged, None if not use_auth else False, publisher="rogue-node", seq=self.rogue_seq)]
        # only a compromised device holds the key; in-path forgers cannot produce a valid MAC
        auth = (attacker == "compromised") if use_auth else None
        return [self._msg(forged, auth)]


class NetworkSimulator:
    def __init__(self, registry: DigitalTwinRegistry, seed: Optional[int] = None,
                 use_auth: bool = False, env_traces: Optional[Dict[str, List[tuple]]] = None):
        self.registry = registry
        self.rng = random.Random(seed)
        self.use_auth = use_auth
        self.env_traces = env_traces or {}
        self.sim_devices: Dict[str, SimulatedDevice] = {}
        self.zones: Dict[str, ZoneEnvironment] = {}
        self.zone_events: List[dict] = []

    def _zone(self, zone: str) -> ZoneEnvironment:
        if zone not in self.zones:
            self.zones[zone] = ZoneEnvironment(zone, random.Random(self.rng.random()),
                                               base_t=24.0 + self.rng.uniform(-2, 2),
                                               base_h=40.0 + self.rng.uniform(-5, 5),
                                               trace=self.env_traces.get(zone))
        return self.zones[zone]

    def _add(self, twin: DeviceTwin) -> None:
        self.registry.register(twin)
        self.sim_devices[twin.device_id] = SimulatedDevice(twin, random.Random(self.rng.random()))

    def build_default_network(self, zones=("Zone-A", "Zone-B", "Zone-C"), live_zone: bool = True) -> None:
        idx = 1
        for zone in zones:
            self._zone(zone)
            gw_id = f"GATE-{idx + 3:03d}"
            for dtype in ["temp_sensor", "humidity_sensor", "motion_sensor"]:
                self._add(DeviceTwin(device_id=f"{dtype[:4].upper()}-{idx:03d}", device_type=dtype,
                                     zone=zone, gateway_id=gw_id))
                idx += 1
            self._add(DeviceTwin(device_id=gw_id, device_type="gateway", zone=zone))
            idx += 1
        # standby devices (one per type per zone). They also measure the
        # zone's physics, so they double as redundancy for the consensus.
        # Zone-Live gives a real MQTT device a simulated standby pool.
        for zone in list(zones) + (["Zone-Live"] if live_zone else []):
            self._zone(zone)
            for dtype in ["temp_sensor", "humidity_sensor", "motion_sensor"]:
                self._add(DeviceTwin(device_id=f"BKP-{dtype[:4].upper()}-{zone.split('-')[-1][0].upper()}", device_type=dtype,
                                     zone=zone, is_backup=True))

    def start_zone_event(self, zone: str, **kw) -> None:
        self._zone(zone).start_event(**kw)
        self.zone_events.append({"zone": zone, "onset": clock.now(), **kw})

    def gateways(self) -> Dict[str, SimulatedDevice]:
        return {d.twin.device_id: d for d in self.sim_devices.values() if d.twin.device_type == "gateway"}

    def tick_all(self, sink: Callable[[Message], None]) -> None:
        for env in self.zones.values():
            env.step()
        gws = self.gateways()
        for sim in self.sim_devices.values():
            for msg in sim.tick(self.zones[sim.twin.zone], gws, self.use_auth):
                sink(msg)

    def get(self, device_id: str) -> Optional[SimulatedDevice]:
        return self.sim_devices.get(device_id)

    def ground_truth(self) -> Dict[str, GroundTruth]:
        return {d: s.gt for d, s in self.sim_devices.items() if s.gt is not None}
