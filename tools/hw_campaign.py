"""
tools/hw_campaign.py
--------------------
The physical-testbed evaluation (Tier A): runs a scripted schedule of
faults on REAL ESP32 devices through their MQTT command topic, records
ground truth with timestamps, then scores what SentinelTwin did by
pulling /api/incidents from the running server. It also writes the
labelled trace that can be released as a dataset.

    # 1) broker + server running, ESP32(s) flashed with arduino/sentineltwin_esp32.ino
    python tools/hw_campaign.py --devices REAL-TEMP-01 --rounds 5
    # -> results/hw/<timestamp>/ground_truth.csv, incidents.json, scores.md

Schedule per round, per device (each step separated by a recovery gap):
    SPIKE, STUCK, DROPOUT, DRIFT, RAMP (compromised-firmware model), FLOOD, WIFI_OFF
The spoofing/rogue-publisher cases need a second publisher - run
tools/test_publisher.py --fault spoof / --fault ramp alongside.
"""

from __future__ import annotations
import argparse
import csv
import json
import time
import urllib.request
from pathlib import Path

import paho.mqtt.client as mqtt

EXPECTED = {"SPIKE": "HARDWARE_FAULT", "STUCK": "HARDWARE_FAULT", "DROPOUT": "HARDWARE_FAULT",
            "DRIFT": "SENSOR_DRIFT", "RAMP": "STEALTHY_TAMPERING", "FLOOD": "DOS_FLOOD_ATTACK",
            "WIFI_OFF": "NETWORK_FAILURE"}
STEPS = [("SPIKE", {}, 40), ("STUCK", {}, 60), ("DROPOUT", {"p": 0.75}, 60), ("DRIFT", {"rate": 0.06}, 150),
         ("RAMP", {"rate": 0.25}, 120), ("FLOOD", {"n": 40}, 30), ("WIFI_OFF", {"s": 45}, 60)]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--broker", default="localhost")
    ap.add_argument("--port", type=int, default=1883)
    ap.add_argument("--server", default="http://localhost:8000")
    ap.add_argument("--devices", nargs="+", default=["REAL-TEMP-01"])
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--gap", type=int, default=150, help="healthy seconds between faults (recovery + re-baseline)")
    args = ap.parse_args()

    out = Path("results/hw") / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    client = mqtt.Client()
    client.connect(args.broker, args.port, keepalive=30)
    client.loop_start()
    gt_rows = []
    print(f"warm-up {args.gap}s so every device has a calibrated baseline...")
    time.sleep(args.gap)
    for rnd in range(args.rounds):
        for fault, params, duration in STEPS:
            for dev in args.devices:
                onset = time.time()
                client.publish(f"sentineltwin/{dev}/cmd", json.dumps({"fault": fault, **params}))
                gt_rows.append({"round": rnd, "device_id": dev, "fault": fault, "expected": EXPECTED[fault],
                                "onset": round(onset, 3), "duration_s": duration, "params": json.dumps(params)})
                print(f"[round {rnd}] {dev}: {fault} for {duration}s")
            time.sleep(duration)
            for dev in args.devices:
                client.publish(f"sentineltwin/{dev}/cmd", json.dumps({"fault": "NONE"}))
            for r in gt_rows[-len(args.devices):]:
                r["cleared"] = round(time.time(), 3)
            time.sleep(args.gap)
    client.loop_stop()

    with open(out / "ground_truth.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(gt_rows[0].keys()))
        w.writeheader()
        w.writerows(gt_rows)
    incidents = json.load(urllib.request.urlopen(f"{args.server}/api/incidents"))
    (out / "incidents.json").write_text(json.dumps(incidents, indent=2), encoding="utf-8")

    lines = ["| fault | device | detected | MTTD s | diagnosed | correct | outcome | MTTR s |", "|---|---|---|---|---|---|---|---|"]
    correct = 0
    for g in gt_rows:
        match = [i for i in incidents if i["device_id"] == g["device_id"]
                 and g["onset"] - 2 <= i["t_detect"] <= g["cleared"] + 30]
        i = match[0] if match else None
        ok = bool(i and i["cause"] == g["expected"])
        correct += ok
        lines.append(f"| {g['fault']} | {g['device_id']} | {bool(i)} | "
                     f"{round(i['t_detect'] - g['onset'], 1) if i else '-'} | {i['cause'] if i else '-'} | {ok} | "
                     f"{i['outcome'] if i else '-'} | "
                     f"{round(i['t_verified'] - i['t_detect'], 1) if i and i.get('t_verified') else '-'} |")
    lines.append(f"\n**First-diagnosis accuracy on hardware: {correct}/{len(gt_rows)}**")
    (out / "scores.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    print(f"\nsaved to {out}")


if __name__ == "__main__":
    main()
