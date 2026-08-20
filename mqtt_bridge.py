"""
mqtt_bridge.py
---------------
Lets a REAL physical device (e.g. an ESP32 + DHT22, see arduino/) feed
into the exact same pipeline as the simulated fleet - same DeviceTwin,
same anomaly detector, same diagnosis rules, same recovery engine.

This is the whole point of the Digital Twin abstraction: nothing in
anomaly_detector.py / diagnosis.py / trust.py / recovery.py cares
whether a reading arrived via simulator.py's random.gauss() or a real
sensor's MQTT publish - both just end up as a dict appended to
twin.history via twin.push_reading().

Wire format
-----------
A device publishes JSON to:

    sentineltwin/<device_id>/telemetry

Payload, e.g. from a real temperature+humidity sensor:

    {
      "device_type": "temp_sensor",   // only needed on first message
      "zone": "Zone-Live",            // only needed on first message
      "temperature": 26.4,
      "humidity_ambient": 41.2,
      "battery": 87.0,
      "signal_strength": 72.0
    }

device_type controls which backup pool it can fail over to (it will
match simulated BKP-TEMP-* devices if device_type="temp_sensor") - a
real device is protected by the same standby fleet as a simulated one.

Any metric keys you send are exactly the metrics the anomaly detector
and diagnosis engine will reason about - you don't have to match the
simulator's exact metric names, but signal_strength/battery/packet_loss
are treated as "environment" metrics (see diagnosis.py) if you want
NETWORK_FAILURE diagnosis to work the same way.

If no MQTT broker is reachable, this module logs one message and the
rest of the app (simulation-only) keeps working exactly as before -
the hardware integration is strictly additive.
"""

from __future__ import annotations
import json
import os
import threading
from typing import Callable, Optional

from digital_twin import DeviceTwin, DigitalTwinRegistry
from security import Firewall, RateTracker, enforce_on_ingest

MQTT_HOST = os.environ.get("SENTINELTWIN_MQTT_HOST", "localhost")
MQTT_PORT = int(os.environ.get("SENTINELTWIN_MQTT_PORT", "1883"))
TOPIC_PREFIX = os.environ.get("SENTINELTWIN_MQTT_TOPIC_PREFIX", "sentineltwin")

LogFn = Optional[Callable[[str, str, str], None]]


def start_mqtt_bridge(registry: DigitalTwinRegistry, firewall: Firewall, rate_tracker: RateTracker,
                       log_event: LogFn = None):
    """Starts a background MQTT client thread. Returns the client, or None
    if the paho-mqtt library isn't installed / broker isn't reachable."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        if log_event:
            log_event("INFO", "SYSTEM", "paho-mqtt not installed - hardware bridge disabled, running simulation-only.")
        return None

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            client.subscribe(f"{TOPIC_PREFIX}/+/telemetry")
            if log_event:
                log_event("INFO", "SYSTEM", f"MQTT bridge connected to {MQTT_HOST}:{MQTT_PORT}, listening for real devices.")
        elif log_event:
            log_event("INFO", "SYSTEM", f"MQTT connect failed (rc={rc}).")

    def on_message(client, userdata, msg):
        try:
            device_id = msg.topic.split("/")[1]
            payload = json.loads(msg.payload.decode())
        except (IndexError, json.JSONDecodeError):
            return

        twin = registry.get(device_id)
        claimed_type = payload.get("device_type")
        claimed_zone = payload.get("zone")

        # SECURITY LAYER runs at the actual network ingestion boundary -
        # a blocked or attack-flagged device is dropped here, before a
        # single reading reaches its twin. This is the real "cut the
        # connection": the bridge simply refuses to ingest the packet.
        if enforce_on_ingest(device_id, twin, firewall, rate_tracker,
                              claimed_type=claimed_type, log_event=log_event):
            return

        if twin is None:
            device_type = payload.pop("device_type", "temp_sensor")
            zone = payload.pop("zone", "Zone-Live")
            twin = DeviceTwin(device_id=device_id, device_type=device_type, zone=zone, is_real=True)
            registry.register(twin)
            if log_event:
                log_event("INFO", device_id, f"Live physical device connected via MQTT ({device_type}, {zone}).")
        else:
            payload.pop("device_type", None)
            payload.pop("zone", None)

        numeric_values = {k: float(v) for k, v in payload.items() if isinstance(v, (int, float))}
        if numeric_values:
            twin.push_reading(numeric_values)

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    def _run():
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_forever()
        except Exception as exc:
            if log_event:
                log_event("INFO", "SYSTEM", f"MQTT bridge could not reach broker at {MQTT_HOST}:{MQTT_PORT} ({exc}) - running simulation-only.")

    threading.Thread(target=_run, daemon=True).start()
    return client
