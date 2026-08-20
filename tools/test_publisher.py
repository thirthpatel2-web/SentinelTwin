"""
tools/test_publisher.py
-------------------------
Publishes fake-but-real-MQTT telemetry so you can verify mqtt_bridge.py
end-to-end without owning an ESP32 yet. This is NOT the same thing as
the simulator - the simulator writes straight into memory; this script
sends actual MQTT messages over the network to whatever broker
SentinelTwin is configured to listen on, exercising the identical code
path a real device would use.

Usage:
    python tools/test_publisher.py                     # normal readings
    python tools/test_publisher.py --fault network      # degraded signal
    python tools/test_publisher.py --device-id REAL-TEMP-02 --zone Zone-B

Requires: pip install paho-mqtt==1.6.1
Requires an MQTT broker running (e.g. `mosquitto` locally) and
SentinelTwin's main.py running with SENTINELTWIN_MQTT_HOST pointing at it.
"""

import argparse
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
parser.add_argument("--fault", choices=["none", "network", "hardware", "flood"], default="none")
parser.add_argument("--count", type=int, default=0, help="0 = run forever")
args = parser.parse_args()

client = mqtt.Client()
client.connect(args.host, args.port, keepalive=30)
client.loop_start()

topic = f"sentineltwin/{args.device_id}/telemetry"
tick = 0

print(f"Publishing to {topic} on {args.host}:{args.port} every {args.interval}s (Ctrl+C to stop)")

try:
    while args.count == 0 or tick < args.count:
        interval = args.interval
        temperature = round(random.gauss(24.0, 0.6), 2)
        humidity = round(random.gauss(40.0, 1.0), 2)
        battery = round(random.gauss(90.0, 0.5), 1)
        signal = round(random.gauss(85.0, 2.0), 1)
        packet_loss = 0.0

        if args.fault == "network" and tick > 5:
            signal = max(0.0, signal - min((tick - 5) * 12, 90))
            packet_loss = min(95.0, (tick - 5) * 15)
        elif args.fault == "hardware" and tick > 5:
            temperature = temperature + random.choice([-1, 1]) * random.uniform(35, 60)
        elif args.fault == "flood" and tick > 5:
            # publish far faster than the device's own normal cadence -
            # this is what the security layer's rate tracker is watching for
            interval = 0.05

        payload = {
            "temperature": temperature,
            "humidity_ambient": humidity,
            "battery": battery,
            "signal_strength": signal,
            "packet_loss": packet_loss,
        }
        if tick == 0:
            payload["device_type"] = args.device_type
            payload["zone"] = args.zone

        client.publish(topic, json.dumps(payload))
        print(f"[{tick}] {payload}")
        tick += 1
        time.sleep(interval)
except KeyboardInterrupt:
    pass
finally:
    client.loop_stop()
    client.disconnect()
