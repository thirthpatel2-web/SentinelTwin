"""
datasets/intel_lab.py
---------------------
Trace-driven evaluation (Tier B): replays REAL indoor temperature and
humidity recorded by the Intel Berkeley Research Lab deployment (54 Mica2
motes, Feb-Apr 2004; Bodik, Hong, Guestrin, Madden, Paskin, Thibaux) as
the physical environment of each SentinelTwin zone, so the detector and
the consensus face real indoor dynamics (HVAC cycles, occupancy, sun)
instead of a synthetic random walk.

    data:   http://db.csail.mit.edu/labdata/data.txt.gz  (~34 MB, whitespace separated:
            date time epoch moteid temperature humidity light voltage)

    from datasets.intel_lab import load_zone_traces
    traces = load_zone_traces("data/intel/data.txt")           # {"Zone-A": [(T, H), ...], ...}
    SentinelEngine(env_traces=traces)

Each zone is the per-epoch median of a group of physically neighbouring
motes (so one zone trace is a real room-scale signal), cleaned of the
dataset's well-known failure modes (readings > 50 degC / humidity < 0 as
batteries die), forward-filled over gaps, and normalised to one reading
per simulator tick.
"""

from __future__ import annotations
import gzip
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

# neighbouring motes in the lab floor plan (by mote id)
ZONE_MOTES = {
    "Zone-A": tuple(range(1, 11)),
    "Zone-B": tuple(range(18, 28)),
    "Zone-C": tuple(range(33, 43)),
}
VALID_T = (5.0, 45.0)
VALID_H = (5.0, 95.0)


def _open(path: Path):
    return gzip.open(path, "rt", encoding="utf-8", errors="replace") if path.suffix == ".gz" else \
        open(path, encoding="utf-8", errors="replace")


def load_zone_traces(path: str, zone_motes: Dict[str, Sequence[int]] = None, max_epochs: int = 20000,
                     start_epoch: int = 1000) -> Dict[str, List[Tuple[float, float]]]:
    zone_motes = zone_motes or ZONE_MOTES
    mote_zone = {m: z for z, motes in zone_motes.items() for m in motes}
    per_epoch: Dict[str, Dict[int, List[Tuple[float, float]]]] = defaultdict(lambda: defaultdict(list))
    with _open(Path(path)) as f:
        for line in f:
            parts = line.split()
            if len(parts) < 6:
                continue
            try:
                epoch, mote, t, h = int(parts[2]), int(parts[3]), float(parts[4]), float(parts[5])
            except ValueError:
                continue
            if not (start_epoch <= epoch < start_epoch + max_epochs) or mote not in mote_zone:
                continue
            if VALID_T[0] <= t <= VALID_T[1] and VALID_H[0] <= h <= VALID_H[1]:
                per_epoch[mote_zone[mote]][epoch].append((t, h))
    traces: Dict[str, List[Tuple[float, float]]] = {}
    for zone, epochs in per_epoch.items():
        series, last = [], None
        for e in range(start_epoch, start_epoch + max_epochs):
            vals = epochs.get(e)
            if vals and len(vals) >= 2:
                last = (statistics.median(v[0] for v in vals), statistics.median(v[1] for v in vals))
            if last is not None:
                series.append(last)
        if len(series) > 500:
            traces[zone] = series
    return traces


def trace_stats(traces: Dict[str, List[Tuple[float, float]]]) -> Dict[str, dict]:
    out = {}
    for z, s in traces.items():
        ts, hs = [x[0] for x in s], [x[1] for x in s]
        out[z] = {"n": len(s), "T_mean": round(statistics.fmean(ts), 2), "T_sd": round(statistics.pstdev(ts), 2),
                  "H_mean": round(statistics.fmean(hs), 2), "H_sd": round(statistics.pstdev(hs), 2),
                  "T_step_sd": round(statistics.pstdev([b - a for a, b in zip(ts, ts[1:])]), 3)}
    return out
