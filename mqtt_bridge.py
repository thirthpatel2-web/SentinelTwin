"""
mqtt_bridge.py
---------------
Lets a REAL physical device (e.g. an ESP32 + DHT22, see arduino/) feed the
exact same pipeline as the simulated fleet. Every MQTT message is turned
into the same Message the simulator emits and handed to the same
Ingestor (ingest.py), so flood detection, identity checks, provenance,
the firewall, consensus, diagnosis and verified recovery all apply to
hardware unchanged.

Wire format
-----------
A device publishes JSON to:

    sentineltwin/<device_id>/telemetry

    {
      "device_type": "temp_sensor",   // first message only (registration)
      "zone": "Zone-Live",            // first message only
      "seq": 1042,                    // monotonically increasing counter (provenance)
      "pub": "REAL-TEMP-01-fw",       // publisher fingerprint (firmware id)
      "temperature": 26.4,
      "humidity_ambient": 41.2,
      "battery": 87.0,
      "signal_strength": 72.0,
      "mac": "9f2c..."                // optional, MUST be the last field (see below)
    }

Message authentication (optional): if SENTINELTWIN_DEVICE_KEYS points at a
JSON file {"<device_id>": "<hex key>"}, the bridge verifies
mac = HMAC-SHA256(key, body) where body is the exact bytes the device sent
with the trailing ,"mac":"<64 hex>" removed - i.e. the device signs the
JSON it actually transmits, so float formatting can never break the check.
Messages failing the check are dropped and recorded as provenance
evidence. Devices with no key configured are accepted unauthenticated.

The bridge can also send commands back on sentineltwin/<device_id>/cmd
(used by tools/hw_campaign.py to inject faults on real hardware with
ground-truth timestamps).

If no broker is reachable the bridge logs once and the rest of the app
keeps running simulation-only - the hardware path is strictly additive.
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import re
import threading
from typing import Callable, Dict, Optional

import clock
from simulator import Message

MQTT_HOST = os.environ.get("SENTINELTWIN_MQTT_HOST", "localhost")
MQTT_PORT = int(os.environ.get("SENTINELTWIN_MQTT_PORT", "1883"))
TOPIC_PREFIX = os.environ.get("SENTINELTWIN_MQTT_TOPIC_PREFIX", "sentineltwin")

LogFn = Optional[Callable[[str, str, str], None]]


def load_keys() -> Dict[str, bytes]:
    path = os.environ.get("SENTINELTWIN_DEVICE_KEYS")
    if not path or not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return {k: bytes.fromhex(v) for k, v in json.load(f).items()}


MAC_SUFFIX = re.compile(rb',"mac":"([0-9a-fA-F]{64})"\}\s*$')


def sign(body: bytes, key: bytes) -> bytes:
    """What a device does: append ,"mac":"..." to the JSON object it is about to send."""
    assert body.rstrip().endswith(b"}")
    mac = hmac.new(key, body.rstrip(), hashlib.sha256).hexdigest().encode()
    return body.rstrip()[:-1] + b',"mac":"' + mac + b'"}'


def verify_mac(raw: bytes, key: Optional[bytes]) -> Optional[bool]:
    if key is None:
        return None
    m = MAC_SUFFIX.search(raw)
    if not m:
        return False
    body = raw[:m.start()] + b"}"
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(m.group(1).decode().lower(), expected)


def to_message(topic: str, raw: bytes, keys: Dict[str, bytes]) -> Optional[Message]:
    try:
        device_id = topic.split("/")[1]
        payload = json.loads(raw.decode())
    except (IndexError, ValueError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    auth = verify_mac(raw, keys.get(device_id))
    seq = payload.pop("seq", None)
    pub = payload.pop("pub", None)
    payload.pop("mac", None)
    return Message(device_id=device_id, payload=payload, seq=int(seq) if isinstance(seq, (int, float)) else None,
                   ts=clock.now(), publisher_id=str(pub) if pub else None, auth_ok=auth)


def start_mqtt_bridge(engine, log_event: LogFn = None):
    """Starts a background MQTT client thread feeding engine.ingestor. Returns the client or None."""
    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        if log_event:
            log_event("INFO", "SYSTEM", "paho-mqtt not installed - hardware bridge disabled, running simulation-only.")
        return None

    keys = load_keys()

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            client.subscribe(f"{TOPIC_PREFIX}/+/telemetry")
            if log_event:
                log_event("INFO", "SYSTEM", f"MQTT bridge connected to {MQTT_HOST}:{MQTT_PORT}"
                          f"{f', {len(keys)} device keys loaded' if keys else ''} - listening for real devices.")
        elif log_event:
            log_event("INFO", "SYSTEM", f"MQTT connect failed (rc={rc}).")

    def on_message(client, userdata, msg):
        m = to_message(msg.topic, msg.payload, keys)
        if m is not None:
            engine.inbox.append(m)   # processed on the engine's own tick, never concurrently

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    engine.mqtt_client = client

    def _run():
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_forever()
        except Exception as exc:
            if log_event:
                log_event("INFO", "SYSTEM", f"MQTT bridge could not reach broker at {MQTT_HOST}:{MQTT_PORT} "
                          f"({exc}) - running simulation-only.")

    threading.Thread(target=_run, daemon=True).start()
    return client
