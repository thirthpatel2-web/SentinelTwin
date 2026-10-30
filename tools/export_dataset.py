"""
tools/export_dataset.py
-----------------------
Generates SentinelTwin-Bench: a labelled telemetry trace in which benign
faults, sensor drift, zone-wide environment changes AND attacks occur on
the same IoT telemetry - the joint ground truth the literature review
found no public dataset provides.

Every row is one message exactly as it arrived at the ingestion boundary
(what any detector would see), plus labels a detector must NOT use:

    t, device_id, zone, device_type, is_backup, seq, publisher, auth_ok,
    <every metric>, true_T, true_H,
    label (NONE | injected mode), label_cause (expected root cause),
    attacker (for TAMPER_RAMP), fault_onset, zone_event

    python tools/export_dataset.py --hours 6 --seed 7 --out results/dataset
    -> results/dataset/sentineltwin_bench_seed7.csv  + schedule.json + README.md

Faults are injected one device at a time at random times on random
eligible devices, with healthy gaps in between; heatwaves are injected on
whole zones. The schedule file lists every injection with its onset.
"""

from __future__ import annotations
import argparse
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import clock                                       # noqa: E402
from config import PipelineConfig                  # noqa: E402
from engine import SentinelEngine                  # noqa: E402
from simulator import TICK_SECONDS, FaultMode, EXPECTED_CAUSE  # noqa: E402

CATALOGUE = [
    ("HARDWARE", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 20),
    ("STUCK", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 60),
    ("DROPOUT", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 60),
    ("NETWORK", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 40),
    ("GATEWAY", {}, ("gateway",), 60),
    ("DRIFT", {"rate": 0.15}, ("temp_sensor", "humidity_sensor"), 120),
    ("DRIFT", {"rate": 0.4}, ("temp_sensor", "humidity_sensor"), 80),
    ("TAMPER", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 20),
    ("TAMPER_RAMP", {"attacker": "fabricate", "slope": 0.25}, ("temp_sensor", "humidity_sensor"), 100),
    ("TAMPER_RAMP", {"attacker": "inpath", "slope": 0.6}, ("temp_sensor", "humidity_sensor"), 80),
    ("TAMPER_RAMP", {"attacker": "rogue", "slope": 0.25}, ("temp_sensor", "humidity_sensor"), 100),
    ("TAMPER_RAMP", {"attacker": "compromised", "slope": 0.15}, ("temp_sensor", "humidity_sensor"), 120),
    ("ON_OFF", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 120),
    ("FLOOD", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 20),
    ("SPOOF", {}, ("temp_sensor", "humidity_sensor", "motion_sensor"), 30),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=6.0, help="simulated hours")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--mac", action="store_true", help="devices sign messages (forgers fail authentication)")
    ap.add_argument("--out", default="results/dataset")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    clock.use(clock.SimClock(1_700_000_000.0))
    engine = SentinelEngine(cfg=PipelineConfig(use_auth=args.mac), seed=args.seed)
    rng = random.Random(args.seed)
    sim = engine.sim
    metrics = sorted({m for d in sim.sim_devices.values() for m in d._physical_values(next(iter(sim.zones.values())))})
    path = out / f"sentineltwin_bench_seed{args.seed}{'_mac' if args.mac else ''}.csv"
    f = open(path, "w", newline="", encoding="utf-8")
    cols = ["t", "device_id", "zone", "device_type", "is_backup", "seq", "publisher", "auth_ok"] + metrics + \
           ["claimed_type", "claimed_zone", "true_T", "true_H", "label", "label_cause", "attacker", "fault_onset", "zone_event"]
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()

    original = engine.ingestor.ingest

    def tap(msg, is_real=False):
        dev = sim.get(msg.device_id)
        twin = engine.registry.get(msg.device_id)
        env = sim.zones[twin.zone]
        gt = dev.gt if dev else None
        row = {"t": round(msg.ts, 3), "device_id": msg.device_id, "zone": twin.zone, "device_type": twin.device_type,
               "is_backup": twin.is_backup, "seq": msg.seq, "publisher": msg.publisher_id, "auth_ok": msg.auth_ok,
               "claimed_type": msg.payload.get("device_type", ""), "claimed_zone": msg.payload.get("zone", ""),
               "true_T": round(env.T, 3), "true_H": round(env.H, 3),
               "label": gt.mode.value if gt else "NONE", "label_cause": gt.expected_cause if gt else "NONE",
               "attacker": gt.params.get("attacker", "") if gt else "",
               "fault_onset": round(gt.onset, 3) if gt else "", "zone_event": bool(env.event)}
        for m in metrics:
            v = msg.payload.get(m)
            row[m] = v if isinstance(v, (int, float)) else ""
        w.writerow(row)
        return original(msg, is_real)

    engine.ingestor.ingest = tap
    total = int(args.hours * 3600 / TICK_SECONDS)
    schedule, busy_until, next_fault, next_heat = [], 0, 80, rng.randint(400, 900)
    primaries = [d for d in sim.sim_devices.values() if not d.twin.is_backup and d.twin.zone != "Zone-Live"]
    for tick in range(total):
        if tick == next_fault and tick >= busy_until:
            fault, params, types, dur = rng.choice(CATALOGUE)
            dev = rng.choice([d for d in primaries if d.twin.device_type in types])
            engine.inject(dev.twin.device_id, fault, **params)
            schedule.append({"tick": tick, "t": clock.now(), "device_id": dev.twin.device_id, "fault": fault,
                             "params": params, "expected_cause": EXPECTED_CAUSE[FaultMode(fault)]})
            busy_until = tick + dur + 120
            next_fault = busy_until + rng.randint(20, 120)
        elif tick == next_fault:
            next_fault = busy_until
        if tick == next_heat:
            zone = rng.choice(["Zone-A", "Zone-B", "Zone-C"])
            engine.zone_event(zone, magnitude_t=rng.uniform(4, 7))
            schedule.append({"tick": tick, "t": clock.now(), "zone": zone, "fault": "HEATWAVE"})
            next_heat = tick + rng.randint(900, 1600)
        # a fault's own duration ends it, unless the closed loop already fixed it
        for item in schedule[-2:]:
            if "device_id" in item and tick == item["tick"] + dict((c[0], c[3]) for c in CATALOGUE)[item["fault"]]:
                d = sim.get(item["device_id"])
                if d.gt is not None and d.repair_in is None:
                    d.clear_fault()
        engine.tick()
    f.close()
    (out / "schedule.json").write_text(json.dumps(schedule, indent=2), encoding="utf-8")
    (out / "README.md").write_text(
        f"# SentinelTwin-Bench (seed {args.seed}{', MAC on' if args.mac else ''})\n\n"
        f"{args.hours} simulated hours, {len([s for s in schedule if 'device_id' in s])} fault/attack injections, "
        f"{len([s for s in schedule if s['fault'] == 'HEATWAVE'])} zone-wide heatwaves. One row per message as received "
        "at the ingestion boundary. Columns `true_T`, `true_H`, `label*`, `attacker`, `fault_onset` and `zone_event` "
        "are ground truth and must not be used as detector inputs. Regenerate with "
        f"`python tools/export_dataset.py --hours {args.hours} --seed {args.seed}{' --mac' if args.mac else ''}`.\n",
        encoding="utf-8")
    print(f"wrote {path} ({len(schedule)} scheduled events)")


if __name__ == "__main__":
    main()
