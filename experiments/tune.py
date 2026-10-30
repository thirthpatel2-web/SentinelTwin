"""
experiments/tune.py
-------------------
Chooses the co-movement evidence parameters on DEVELOPMENT seeds
(1000-1019) that never appear in the reported evaluation (seeds 0-29), so
the reported numbers are not tuned on their own test data.

Objective: balanced first-diagnosis accuracy between the two cases the
co-movement evidence exists to separate - benign drift and a fabricating
attacker - minus the benign-drift false-quarantine rate.

    python -m experiments.tune
"""

from __future__ import annotations
import itertools
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import PipelineConfig                    # noqa: E402
from experiments.harness import Episode, run_episode  # noqa: E402

DEV_SEEDS = range(1000, 1020)
CASES = [("DRIFT", {"rate": 0.1}), ("DRIFT", {"rate": 0.25}),
         ("TAMPER_RAMP", {"attacker": "fabricate", "slope": 0.1}),
         ("TAMPER_RAMP", {"attacker": "fabricate", "slope": 0.25})]
GRID = list(itertools.product([0.0, 0.1, 0.2], [1.0, 1.5, 2.5]))


def _job(args):
    (thr, w), (fault, params), seed = args
    r = run_episode(Episode(fault, seed, params), replace(PipelineConfig(), comove_threshold=thr, comove_weight=w))
    return thr, w, fault, r["correct_first"], r["false_quarantine"]


def main() -> None:
    jobs = [(g, c, s) for g in GRID for c in CASES for s in DEV_SEEDS]
    with ProcessPoolExecutor() as pool:
        rows = list(pool.map(_job, jobs, chunksize=4))
    results = []
    for thr, w in GRID:
        mine = [r for r in rows if r[0] == thr and r[1] == w]
        drift = [r for r in mine if r[2] == "DRIFT"]
        fab = [r for r in mine if r[2] == "TAMPER_RAMP"]
        acc_d = sum(r[3] for r in drift) / len(drift)
        acc_f = sum(r[3] for r in fab) / len(fab)
        fq = sum(r[4] for r in drift) / len(drift)
        results.append({"threshold": thr, "weight": w, "drift_acc": round(acc_d, 3), "fabricate_acc": round(acc_f, 3),
                        "drift_false_quarantine": round(fq, 3), "objective": round((acc_d + acc_f) / 2 - fq, 3)})
    results.sort(key=lambda r: -r["objective"])
    out = Path(__file__).resolve().parents[1] / "results" / "tuning.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2), encoding="utf-8")
    for r in results:
        print(r)


if __name__ == "__main__":
    main()
