"""
simulator.py
------------
Simulates a small IoT network (sensors + gateways) generating telemetry
every tick. Devices normally emit smooth, correlated readings. On demand
(or randomly, at low probability, for demo liveliness) a device can be
pushed into one of four fault modes so the rest of the pipeline
(anomaly detection -> diagnosis -> trust -> recovery) has something real
to react to:

  HARDWARE   -> a single metric spikes/flatlines while others stay normal
                (classic sensor/board failure signature)
  NETWORK    -> signal_strength collapses and packet_loss spikes, values
                go stale/missing (classic connectivity failure signature)
  DRIFT      -> a metric slowly drifts away from baseline over many ticks
                (classic calibration / aging-sensor signature)
  MALICIOUS  -> multiple metrics jump together to implausible, physically
                inconsistent values instantly (classic spoofing/injection
                signature) while signal_strength stays perfect (an attacker
                doesn't want to look disconnected)
"""

from __future__ import annotations
import random
from enum import Enum
from typing import Dict, Optional

from digital_twin import DeviceTwin, DigitalTwinRegistry, DeviceState


class FaultMode(str, Enum):
    NONE = "NONE"
    HARDWARE = "HARDWARE"
    NETWORK = "NETWORK"
    DRIFT = "DRIFT"
    MALICIOUS = "MALICIOUS"


DEVICE_BLUEPRINT = {
    # device_type: (baseline values, noise). Each type senses two physical
    # quantities besides battery/signal so that "multiple metrics jumping
    # together" (the malicious-tampering signature) is actually possible -
    # a single-metric device can only ever show a single-metric fault.
    "temp_sensor": {
        "temperature": (24.0, 0.6), "humidity_ambient": (40.0, 1.0),
        "battery": (90.0, 0.5), "signal_strength": (85.0, 2.0),
    },
    "humidity_sensor": {
        "humidity": (45.0, 1.2), "temperature_ambient": (23.0, 0.6),
        "battery": (88.0, 0.5), "signal_strength": (82.0, 2.0),
    },
    "motion_sensor": {
        "motion_events": (2.0, 0.3), "vibration_level": (0.5, 0.15),
        "battery": (75.0, 0.5), "signal_strength": (80.0, 2.0),
    },
    "gateway": {
        "throughput_mbps": (120.0, 4.0), "cpu_load_pct": (35.0, 3.0),
        "battery": (100.0, 0.0), "signal_strength": (95.0, 1.0),
    },
}
ENV_METRICS = ("battery", "signal_strength", "packet_loss")


class SimulatedDevice:
    def __init__(self, twin: DeviceTwin):
        self.twin = twin
        self.fault_mode: FaultMode = FaultMode.NONE
        self.fault_ticks: int = 0
        self.drift_offset: float = 0.0
        self.packet_loss: float = 0.0
        self._drift_metric: Optional[str] = None

    def inject_fault(self, mode: FaultMode) -> None:
        self.fault_mode = mode
        self.fault_ticks = 0
        self.drift_offset = 0.0
        self._drift_metric = None

    def clear_fault(self) -> None:
        self.fault_mode = FaultMode.NONE
        self.fault_ticks = 0
        self.drift_offset = 0.0
        self.packet_loss = 0.0
        self._drift_metric = None

    def tick(self) -> Dict[str, float]:
        blueprint = DEVICE_BLUEPRINT[self.twin.device_type]
        values: Dict[str, float] = {}
        for metric, (baseline, noise) in blueprint.items():
            values[metric] = round(random.gauss(baseline, noise), 2)
        values["packet_loss"] = 0.0
        self.fault_ticks += 1

        if self.fault_mode == FaultMode.HARDWARE:
            # exactly one sensed metric flatlines or spikes hard
            candidates = [m for m in blueprint if m not in ENV_METRICS]
            main_metric = random.choice(candidates)
            spike = random.choice([-1, 1]) * random.uniform(35, 60)
            values[main_metric] = round(blueprint[main_metric][0] + spike, 2)

        elif self.fault_mode == FaultMode.NETWORK:
            values["signal_strength"] = max(0.0, round(blueprint["signal_strength"][0] - min(self.fault_ticks * 12, 90), 2))
            self.packet_loss = min(95.0, self.packet_loss + 15)
            values["packet_loss"] = round(self.packet_loss, 2)

        elif self.fault_mode == FaultMode.DRIFT:
            candidates = [m for m in blueprint if m not in ENV_METRICS]
            if not hasattr(self, "_drift_metric") or self._drift_metric is None:
                self._drift_metric = random.choice(candidates)
            main_metric = self._drift_metric
            self.drift_offset += random.uniform(1.2, 2.5)
            values[main_metric] = round(values[main_metric] + self.drift_offset, 2)

        elif self.fault_mode == FaultMode.MALICIOUS:
            # multiple sensed metrics jump together, instantly, implausibly -
            # but signal stays perfect (attacker hides connectivity issues)
            for metric in blueprint:
                if metric in ENV_METRICS:
                    continue
                values[metric] = round(blueprint[metric][0] * random.uniform(3.0, 5.0), 2)
            values["signal_strength"] = round(blueprint["signal_strength"][0] + random.uniform(0, 1), 2)

        return values


class NetworkSimulator:
    def __init__(self, registry: DigitalTwinRegistry):
        self.registry = registry
        self.sim_devices: Dict[str, SimulatedDevice] = {}

    def build_default_network(self) -> None:
        zones = ["Zone-A", "Zone-B", "Zone-C"]
        idx = 1
        for zone in zones:
            for dtype in ["temp_sensor", "humidity_sensor", "motion_sensor"]:
                dev_id = f"{dtype[:4].upper()}-{idx:03d}"
                twin = DeviceTwin(device_id=dev_id, device_type=dtype, zone=zone)
                self.registry.register(twin)
                self.sim_devices[dev_id] = SimulatedDevice(twin)
                idx += 1
            # one gateway per zone
            gw_id = f"GATE-{idx:03d}"
            gw_twin = DeviceTwin(device_id=gw_id, device_type="gateway", zone=zone)
            self.registry.register(gw_twin)
            self.sim_devices[gw_id] = SimulatedDevice(gw_twin)
            idx += 1

        # standby backup devices (one per type, shared pool per zone) -
        # includes Zone-Live so a real physical device (see mqtt_bridge.py)
        # can fail over to a simulated standby exactly like a simulated one
        for zone in zones + ["Zone-Live"]:
            for dtype in ["temp_sensor", "humidity_sensor", "motion_sensor"]:
                dev_id = f"BKP-{dtype[:4].upper()}-{zone[-1]}"
                twin = DeviceTwin(device_id=dev_id, device_type=dtype, zone=zone, is_backup=True)
                self.registry.register(twin)
                self.sim_devices[dev_id] = SimulatedDevice(twin)

    def tick_all(self) -> None:
        for dev_id, sim in self.sim_devices.items():
            twin = sim.twin
            if twin.state == DeviceState.ISOLATED:
                # isolated devices are cut off from the pipeline - no live data flows
                continue
            values = sim.tick()
            twin.push_reading(values)

    def get(self, device_id: str) -> Optional[SimulatedDevice]:
        return self.sim_devices.get(device_id)
