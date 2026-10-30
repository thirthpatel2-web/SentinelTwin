"""
ingest.py
---------
The single ingestion boundary for EVERY message - simulated or from real
hardware over MQTT. Because both go through this function, every
transport-level attack (flood, identity spoofing, rogue publishers,
forged messages) can be exercised in simulation and on hardware with the
identical code path.

Order of checks for each message:
  1. firewall (device- or publisher-scoped)  -> drop
  2. isolated device                         -> drop (it is cut off)
  3. message-rate flood                      -> block + DOS_FLOOD_ATTACK
  4. identity claims vs registration         -> block + IDENTITY_SPOOFING
  5. provenance (seq / publisher / MAC)      -> evidence; failed MACs dropped
  6. numeric values pushed into the twin
"""

from __future__ import annotations
from typing import Callable, Optional

import clock
from config import PipelineConfig
from digital_twin import DeviceTwin, DeviceState, DigitalTwinRegistry
from security import Firewall, RateTracker, note_provenance, publisher_key

LogFn = Callable[[str, str, str], None]


class Ingestor:
    def __init__(self, registry: DigitalTwinRegistry, firewall: Firewall, rate: RateTracker,
                 cfg: PipelineConfig, log_event: LogFn, recovery=None) -> None:
        self.registry = registry
        self.firewall = firewall
        self.rate = rate
        self.cfg = cfg
        self.log = log_event
        self.recovery = recovery          # for publisher fingerprints used by scoped quarantine
        self.dropped = 0
        self.genuine_dropped: dict = {}   # firewall drops of the device's OWN publisher (collateral)

    def _flag(self, twin: Optional[DeviceTwin], cause: str, msg: str) -> None:
        if twin is None:
            return
        if twin.state == DeviceState.ANOMALOUS and twin.root_cause == cause:
            return
        if twin.incident_id is None or twin.state in (DeviceState.NORMAL, DeviceState.RECOVERED, DeviceState.SUSPECT):
            twin.suspect_since = twin.suspect_since or clock.now()
        twin.state = DeviceState.ANOMALOUS
        twin.root_cause = cause
        twin.root_cause_confidence = 0.9
        twin.posterior = {cause: 0.9, "UNCLASSIFIED_ANOMALY": 0.1}
        twin.explanation = [msg]
        twin.recovery_log.append(f"[FIREWALL] {msg}")

    def ingest(self, msg, is_real: bool = False) -> bool:
        """Returns True if the message was accepted into the twin."""
        device_id = msg.device_id
        payload = dict(msg.payload)
        pub = msg.publisher_id
        twin = self.registry.get(device_id)

        if self.firewall.is_blocked(device_id) or (pub and self.firewall.is_blocked(publisher_key(device_id, pub))):
            self.dropped += 1
            if twin:
                twin.messages_dropped += 1
                if pub is None or twin.publisher_id is None or pub == twin.publisher_id:
                    self.genuine_dropped[device_id] = self.genuine_dropped.get(device_id, 0) + 1
            return False
        if twin is not None and twin.state == DeviceState.ISOLATED:
            self.dropped += 1
            return False

        foreign = twin is not None and twin.publisher_id is not None and pub is not None and pub != twin.publisher_id
        if foreign and self.recovery is not None:
            self.recovery.foreign_publisher[device_id] = pub

        if self.cfg.security_layer:
            if self.rate.record(device_id, msg.ts):
                key = publisher_key(device_id, pub) if (foreign and self.cfg.scoped_quarantine) else device_id
                duration = self.firewall.block(key, "DOS_FLOOD_ATTACK")
                if twin and key == device_id:
                    twin.firewall_blocked = True
                    twin.firewall_reason = "DOS_FLOOD_ATTACK"
                self._flag(twin, "DOS_FLOOD_ATTACK", f"Message rate far above this device's learned cadence - "
                           f"connection cut for {_fmt(duration)} (suspected DoS flood).")
                self.log("FIREWALL", device_id, f"Connection cut for {_fmt(duration)} - DoS/flood pattern.")
                return False
            claimed_type, claimed_zone = payload.get("device_type"), payload.get("zone")
            if twin is not None and ((claimed_type and claimed_type != twin.device_type)
                                     or (claimed_zone and claimed_zone != twin.zone)):
                scoped = foreign and self.cfg.scoped_quarantine
                key = publisher_key(device_id, pub) if scoped else device_id
                duration = self.firewall.block(key, "IDENTITY_SPOOFING")
                if not scoped:
                    twin.firewall_blocked = True
                    twin.firewall_reason = "IDENTITY_SPOOFING"
                claim = claimed_type if claimed_type != twin.device_type else claimed_zone
                self._flag(twin, "IDENTITY_SPOOFING",
                           f"Message claimed '{claim}' but {device_id} registered as {twin.device_type}/{twin.zone} - "
                           f"{'impostor publisher' if scoped else 'device'} blocked for {_fmt(duration)}.")
                self.log("FIREWALL", device_id, f"Identity mismatch - {'impostor' if scoped else 'device'} "
                         f"blocked for {_fmt(duration)}.")
                return False

        if twin is None:
            twin = DeviceTwin(device_id=device_id, device_type=str(payload.get("device_type", "temp_sensor")),
                              zone=str(payload.get("zone", "Zone-Live")), is_real=is_real)
            self.registry.register(twin)
            self.log("INFO", device_id, f"New device registered ({twin.device_type}, {twin.zone})"
                     + (" - live hardware over MQTT." if is_real else "."))

        if self.cfg.use_provenance:
            issues = note_provenance(twin, msg.seq, pub, msg.auth_ok, msg.ts)
            if "auth_failure" in issues:
                self.dropped += 1
                return False   # an unauthenticated message never reaches the twin's data
        values = {k: float(v) for k, v in payload.items()
                  if isinstance(v, (int, float)) and not isinstance(v, bool) and k not in ("seq",)}
        if values:
            twin.push_reading(values, ts=msg.ts)
        return True


def _fmt(duration: float) -> str:
    return "ever" if duration == float("inf") else f"{int(duration)}s"
