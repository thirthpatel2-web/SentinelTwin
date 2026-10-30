"""
experiments/run_all.py
----------------------
Runs every experiment suite in parallel and writes raw per-episode
records to results/raw/<suite>.jsonl. experiments/report.py turns those
into tables and figures.

    python -m experiments.run_all                 # everything (minutes on a laptop)
    python -m experiments.run_all --suites main ramp --seeds 10   # quick look

Suites
  main       every fault class x seeds, full pipeline                      (RQ1)
  ablation   the main suite under each ablated / baseline configuration    (RQ2, RQ4)
  ramp       slow drift-shaped tampering: attacker model x slope x MAC,
             plus benign drift at the same slopes - the separability curve (RQ3)
  env        zone-wide physical events with and without zone consensus     (RQ2)
  trust      ON-OFF attacker under each trust model                        (RQ5)
  quiet      fault-free long runs: false alarms per device-hour
"""

from __future__ import annotations
import argparse
import json
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Iterable, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import PipelineConfig                    # noqa: E402
from experiments.harness import Episode, run_episode  # noqa: E402

RESULTS = Path(__file__).resolve().parents[1] / "results" / "raw"
FULL = PipelineConfig()

MAIN_FAULTS = [
    ("HARDWARE", {}), ("STUCK", {}), ("DROPOUT", {}), ("NETWORK", {}), ("GATEWAY", {}), ("DRIFT", {}),
    ("TAMPER", {}), ("TAMPER_RAMP", {"attacker": "fabricate", "slope": 0.25}),
    ("TAMPER_RAMP", {"attacker": "rogue", "slope": 0.25}), ("FLOOD", {}), ("SPOOF", {}),
]

ABLATIONS = {
    "full": FULL,
    "no_security_layer": replace(FULL, security_layer=False),
    "no_consensus": replace(FULL, use_consensus=False),
    "rolling_only": replace(FULL, use_consensus=False, use_frozen_baseline=False),
    "no_provenance": replace(FULL, use_provenance=False),
    "no_comovement": replace(FULL, use_comovement=False),
    "no_rate_prior": replace(FULL, use_rate_prior=False),
    "argmax_policy": replace(FULL, policy="argmax"),
    "naive_restart": replace(FULL, policy="naive_restart"),
    "no_heal": replace(FULL, policy="no_heal"),
    "no_verification": replace(FULL, verify=False),
    "permanent_block": replace(FULL, permanent_block=True),
    "device_scoped_block": replace(FULL, scoped_quarantine=False),
    "rate_mu3sigma": replace(FULL, rate_detector="mu3sigma"),
    "with_mac": replace(FULL, use_auth=True),
}

RAMP_SLOPES = [0.05, 0.1, 0.2, 0.3, 0.4, 0.6, 0.8, 1.0]
ATTACKERS = ["fabricate", "inpath", "rogue", "compromised"]


def suite_jobs(name: str, seeds: int) -> Iterable[Tuple[str, Episode, PipelineConfig, str]]:
    if name == "main":
        for fault, params in MAIN_FAULTS:
            for s in range(seeds):
                yield name, Episode(fault, s, params), FULL, "full"
    elif name == "ablation":
        for cname, cfg in ABLATIONS.items():
            if cname == "full":
                continue
            for fault, params in MAIN_FAULTS:
                for s in range(max(10, seeds // 2)):
                    yield name, Episode(fault, s, params), cfg, cname
    elif name == "ramp":
        for slope in RAMP_SLOPES:
            for s in range(seeds):
                yield name, Episode("DRIFT", s, {"rate": slope}), FULL, "full"
                for att in ATTACKERS:
                    for mac in (False, True):
                        cfg = replace(FULL, use_auth=mac)
                        yield name, Episode("TAMPER_RAMP", s, {"attacker": att, "slope": slope}), cfg, \
                            f"full{'_mac' if mac else ''}"
    elif name == "env":
        for cname in ("full", "no_consensus"):
            for s in range(seeds):
                yield name, Episode("NONE", s, zone_event={"magnitude_t": 6.0, "ramp_ticks": 15, "hold_ticks": 80}), \
                    ABLATIONS[cname], cname
                # a real heatwave AND a drifting sensor at once: consensus must still find the sensor
                yield name, Episode("DRIFT", s, {}, zone_event={"magnitude_t": 6.0, "ramp_ticks": 15, "hold_ticks": 80}), \
                    ABLATIONS[cname], cname
    elif name == "trust":
        for model in ("ema", "asym", "beta"):
            for s in range(seeds):
                yield name, Episode("ON_OFF", s, {"on_ticks": 4, "off_ticks": 26, "persistent": True}, run_ticks=480), \
                    replace(FULL, trust_model=model), model
    elif name == "quiet":
        for s in range(seeds):
            yield name, Episode("NONE", s, run_ticks=1200), FULL, "full"
            yield name, Episode("NONE", s, run_ticks=1200), ABLATIONS["no_consensus"], "no_consensus"
    elif name == "intel":
        # Tier B: every zone's physics replayed from the real Intel Berkeley Lab traces
        if not INTEL_PATH.exists():
            print(f"skipping intel suite: {INTEL_PATH} not found (see datasets/intel_lab.py)")
            return
        for fault, params in MAIN_FAULTS + [("NONE", {})]:
            for s in range(seeds):
                yield name, Episode(fault, s, params), FULL, "full_intel"
    else:
        raise ValueError(name)


INTEL_PATH = Path(__file__).resolve().parents[1] / "data" / "intel" / "data.txt.gz"
_TRACES = None


def _run(job):
    global _TRACES
    suite, ep, cfg, cname = job
    traces = None
    if suite == "intel":
        if _TRACES is None:   # loaded once per worker process
            from datasets.intel_lab import load_zone_traces
            _TRACES = load_zone_traces(str(INTEL_PATH))
        # each seed replays a different window of the real recording
        offset = (ep.seed * 397) % 15000
        traces = {z: t[offset:] + t[:offset] for z, t in _TRACES.items()}
    rec = run_episode(ep, cfg, cname, env_traces=traces)
    rec["suite"] = suite
    return rec


def main(argv: List[str] = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suites", nargs="*", default=["main", "ablation", "ramp", "env", "trust", "quiet", "intel"])
    ap.add_argument("--seeds", type=int, default=30)
    ap.add_argument("--workers", type=int, default=0)
    args = ap.parse_args(argv)
    RESULTS.mkdir(parents=True, exist_ok=True)
    import os
    workers = args.workers or max(1, (os.cpu_count() or 2) - 1)
    for suite in args.suites:
        seeds = args.seeds if suite != "quiet" else max(5, args.seeds // 3)
        jobs = list(suite_jobs(suite, seeds))
        t0 = time.time()
        with ProcessPoolExecutor(max_workers=workers) as pool:
            records = list(pool.map(_run, jobs, chunksize=4))
        with open(RESULTS / f"{suite}.jsonl", "w", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")
        print(f"{suite:9s} {len(records):5d} episodes in {time.time() - t0:6.1f}s -> {RESULTS / (suite + '.jsonl')}")


if __name__ == "__main__":
    main()
