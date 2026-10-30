"""
tools/test_publisher.py
-------------------------
Publishes real MQTT telemetry so you can exercise mqtt_bridge.py end to end
without an ESP32. It sends actual MQTT messages to the broker SentinelTwin
listens on - the same code path a real device uses (seq, publisher
fingerprint, optional HMAC).

Usage:
    python tools/test_publisher.py                          # normal readings
    python tools/test_publisher.py --fault network          # degraded link
    python tools/test_publisher.py --fault drift            # slow benign drift
    python tools/test_publisher.py --fault ramp             # same ramp, but sent by a ROGUE publisher
    python tools/test_publisher.py --fault flood            # DoS burst
    python tools/test_publisher.py --fault spoof            # identity claim mismatch from an impostor
    python tools/test_publisher.py --key 00..(64 hex)       # sign every message (HMAC-SHA256)

Requires: pip install paho-mqtt==1.6.1 and an MQTT broker (e.g. mosquitto).
"""

import argparse
import hashlib
import hmac
import json
import random
import time

import paho.mqtt.client as mqtt

parser = argparse.ArgumentParser()
parser.add_argument("--host", default="localhost")
parser.add_argument("--port", type=int, default=1883)
parser.add_argument("--device-id", default="REAL-TEMP-01")
parser.add_argument("--zone", default="Zone-Live")
parser.add_argument("--device-type", default="temp_sensor")
parser.add_argument("--interval", type=float, default=2.0)
parser.add_argument("--fault", choices=["none", "network", "hardware", "flood", "drift", "ramp", "spoof"], default="none")
parser.add_argument("--fault-after", type=int, default=20, help="healthy readings before the fault starts")
parser.add_argument("--key", default="", help="64 hex chars: sign messages with HMAC-SHA256")
parser.add_argument("--count", type=int, default=0, help="0 = run forever")
args = parser.parse_args()

key = bytes.fromhex(args.key) if args.key else None
client = mqtt.Client()
client.connect(args.host, args.port, keepalive=30)
client.loop_start()
topic = f"sentineltwin/{args.device_id}/telemetry"
seq, rogue_seq, offset = random.randint(0, 1000), random.randint(5000, 9000), 0.0
print(f"Publishing to {topic} on {args.host}:{args.port} every {args.interval}s (Ctrl+C to stop)")


def send(body: dict) -> None:
    raw = json.dumps(body, separators=(",", ":")).encode()
    if key is not None and body.get("pub", "").endswith("-fw"):
        mac = hmac.new(key, raw, hashlib.sha256).hexdigest().encode()
        raw = raw[:-1] + b',"mac":"' + mac + b'"}'
    client.publish(topic, raw)


tick = 0
try:
    while args.count == 0 or tick < args.count:
        interval = args.interval
        faulty = args.fault != "none" and tick >= args.fault_after
        temperature = round(random.gauss(24.0, 0.25), 2)
        humidity = round(random.gauss(40.0, 0.6), 2)
        signal, packet_loss = round(random.gauss(85.0, 2.0), 1), 0.0
        k = tick - args.fault_after
        if faulty and args.fault == "network":
            signal, packet_loss = max(0.0, signal - min(k * 12, 90)), min(95.0, k * 15)
        elif faulty and args.fault == "hardware":
            temperature += random.choice([-1, 1]) * random.uniform(35, 60)
        elif faulty and args.fault == "drift":
            offset += 0.06
            temperature += offset
        elif faulty and args.fault == "flood":
            interval = 0.05
        seq += 1
        body = {"seq": seq, "pub": f"{args.device_id}-fw", "temperature": round(temperature, 2),
                "humidity_ambient": humidity, "battery": 90.0, "signal_strength": signal, "packet_loss": packet_loss}
        if tick == 0:
            body = {"device_type": args.device_type, "zone": args.zone, **body}
        send(body)
        if faulty and args.fault == "ramp":
            offset += 0.06
            rogue_seq += 1
            send({"seq": rogue_seq, "pub": "rogue-node", "temperature": round(temperature + offset, 2),
                  "humidity_ambient": humidity, "battery": 90.0, "signal_strength": signal, "packet_loss": 0.0})
        if faulty and args.fault == "spoof":
            rogue_seq += 1
            send({"device_type": "gateway", "zone": args.zone, "seq": rogue_seq, "pub": "rogue-node",
                  "throughput_mbps": 120.0, "cpu_load_pct": 30.0})
        print(f"[{tick}] {body}")
        tick += 1
        time.sleep(interval)
except KeyboardInterrupt:
    pass
finally:
    client.loop_stop()
    client.disconnect()
