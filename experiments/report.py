"""
experiments/report.py
---------------------
Turns results/raw/*.jsonl into the paper's tables and figures:

    results/RESULTS.md       every table, as markdown (also the table view of each figure)
    results/summary.json     the headline numbers, machine-readable
    results/figs/*.png|pdf   confusion matrix, separability curve, trust trajectories, ablations

    python -m experiments.report

Rates come with 95% Wilson intervals; times are medians with IQR.
"""

from __future__ import annotations
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RAW, OUT, FIGS = ROOT / "results" / "raw", ROOT / "results", ROOT / "results" / "figs"

# validated categorical order (dataviz reference palette, light mode); markers carry identity too
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARKERS = ["o", "s", "^", "D", "v", "P", "X", "*"]
INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
BLUES = ["#fcfcfb", "#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b"]

CAUSE_ORDER = ["HARDWARE_FAULT", "NETWORK_FAILURE", "GATEWAY_FAILURE", "SENSOR_DRIFT", "MALICIOUS_TAMPERING",
               "STEALTHY_TAMPERING", "DOS_FLOOD_ATTACK", "IDENTITY_SPOOFING"]
SHORT = {"HARDWARE_FAULT": "Hardware", "NETWORK_FAILURE": "Network", "GATEWAY_FAILURE": "Gateway",
         "UPSTREAM_FAILURE": "Upstream", "SENSOR_DRIFT": "Drift", "MALICIOUS_TAMPERING": "Tamper",
         "STEALTHY_TAMPERING": "Stealth FDI", "DOS_FLOOD_ATTACK": "DoS flood", "IDENTITY_SPOOFING": "Spoofing",
         "UNCLASSIFIED_ANOMALY": "Unclassified", "NONE": "Missed"}
ATTACK_CAUSES = {"MALICIOUS_TAMPERING", "STEALTHY_TAMPERING", "DOS_FLOOD_ATTACK", "IDENTITY_SPOOFING"}


def load(name: str) -> List[dict]:
    p = RAW / f"{name}.jsonl"
    return [json.loads(l) for l in open(p, encoding="utf-8")] if p.exists() else []


def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float, float]:
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def rate(rows: List[dict], key, n_rows: Optional[List[dict]] = None) -> str:
    n_rows = rows if n_rows is None else n_rows
    k = sum(1 for r in n_rows if (key(r) if callable(key) else r[key]))
    p, lo, hi = wilson(k, len(n_rows))
    return "-" if not n_rows else f"{100 * p:.1f} [{100 * lo:.0f}-{100 * hi:.0f}]"


def med(vals: List[float]) -> str:
    vals = [v for v in vals if v is not None]
    if not vals:
        return "-"
    if len(vals) < 4:
        return f"{statistics.median(vals):.1f}"
    q = statistics.quantiles(vals, n=4)
    return f"{statistics.median(vals):.1f} [{q[0]:.1f}-{q[2]:.1f}]"


def mean(vals: List[float]) -> float:
    vals = [v for v in vals if v is not None]
    return sum(vals) / len(vals) if vals else float("nan")


def handled(r: dict) -> bool:
    """Correct final diagnosis - or an attack neutralised before it ever reached the data."""
    return bool(r["correct_final"] or r.get("neutralised"))


def fault_label(r: dict) -> str:
    return f"{r['fault']}({r['attacker']})" if r.get("attacker") else r["fault"]


def table(header: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    out += ["| " + " | ".join(str(c) for c in row) + " |" for row in rows]
    return "\n".join(out)


def style(ax, title: str, xlabel: str = "", ylabel: str = "") -> None:
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", fontsize=11, color=INK, pad=10)
    ax.set_xlabel(xlabel, color=INK2, fontsize=9)
    ax.set_ylabel(ylabel, color=INK2, fontsize=9)
    ax.tick_params(colors=INK2, labelsize=8, length=0)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)


def save(fig, name: str) -> None:
    FIGS.mkdir(parents=True, exist_ok=True)
    fig.patch.set_facecolor(SURFACE)
    fig.tight_layout()
    fig.savefig(FIGS / f"{name}.png", dpi=200)
    fig.savefig(FIGS / f"{name}.pdf")
    plt.close(fig)


# ---------------------------------------------------------------------------
def rq1_main(rows: List[dict], md: List[str], summary: dict, title: str = None, key: str = "rq1",
             fig_name: str = "fig_confusion_matrix") -> None:
    md.append(title or "## RQ1 - Detection, diagnosis and verified recovery per fault class (full pipeline)\n")
    rows = [r for r in rows if r["fault"] != "NONE"]
    groups: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        groups[fault_label(r)].append(r)
    body = []
    for name, g in groups.items():
        body.append([name, SHORT.get(g[0]["expected"], g[0]["expected"]), len(g), rate(g, "detected"),
                     med([r["mttd"] for r in g]), rate(g, "correct_first"), rate(g, "correct_final"),
                     rate(g, lambda r: r["outcome"] == "RECOVERED"), med([r["mttr"] for r in g]),
                     f"{mean([r['exposure_ticks'] for r in g]):.1f}", f"{mean([r['outage_ticks'] for r in g]):.1f}",
                     rate(g, "false_quarantine")])
    md.append(table(["Injected fault", "True cause", "n", "Detected %", "MTTD s", "1st diagnosis correct %",
                     "Final correct %", "Verified recovery %", "MTTR s", "Exposure (ticks)", "Outage (ticks)",
                     "False quarantine %"], body))
    md.append("\nMTTD = onset to detection; MTTR = detection to verified recovery (median [IQR], simulated seconds, "
              "1 tick = 1.5 s). Exposure = ticks on which a wrong reading was accepted as trusted. "
              "Rates: % [95% Wilson CI].\n")

    labels = [c for c in CAUSE_ORDER if any(r["expected"] == c for r in rows)]
    preds = labels + ["UNCLASSIFIED_ANOMALY", "NONE"]
    cm = [[sum(1 for r in rows if r["expected"] == t and r["first_cause"] == p) for p in preds] for t in labels]
    f1s = []
    for i, c in enumerate(labels):
        tp = cm[i][i]
        fp = sum(1 for r in rows if r["first_cause"] == c and r["expected"] != c)
        fn = sum(cm[i]) - tp
        f1s.append(2 * tp / (2 * tp + fp + fn) if tp else 0.0)
    macro = sum(f1s) / len(f1s) if f1s else float("nan")
    acc = sum(r["correct_first"] for r in rows) / len(rows)
    summary[key] = {"episodes": len(rows), "first_diagnosis_accuracy": round(acc, 4), "macro_f1_first": round(macro, 4),
                      "final_accuracy": round(sum(r["correct_final"] for r in rows) / len(rows), 4),
                      "verified_recovery_rate": round(sum(r["outcome"] == "RECOVERED" for r in rows) / len(rows), 4),
                      "false_quarantine_rate_benign": round(mean([float(r["false_quarantine"]) for r in rows if not r["is_attack"]]), 4),
                      "collateral_incidents_per_episode": round(mean([r["other_incidents"] for r in rows]), 3),
                      "gateway_child_isolations": sum(r["child_isolations"] for r in rows)}
    md.append(f"**First-diagnosis accuracy {100 * acc:.1f}%, macro-F1 {macro:.3f}** over {len(rows)} episodes. "
              f"Per-class F1: " + ", ".join(f"{SHORT[c]} {f:.2f}" for c, f in zip(labels, f1s)) + ".\n")
    md.append("Confusion matrix (rows = true cause, columns = first diagnosis):\n")
    md.append(table(["true \\ diagnosed"] + [SHORT.get(p, p) for p in preds],
                    [[SHORT[t]] + [str(v) for v in cm[i]] for i, t in enumerate(labels)]))
    md.append("")

    fig, ax = plt.subplots(figsize=(7.2, 4.6))
    norm = [[v / max(1, sum(row)) for v in row] for row in cm]
    for i, row in enumerate(norm):
        for j, v in enumerate(row):
            color = BLUES[min(len(BLUES) - 1, int(round(v * (len(BLUES) - 1))))]
            ax.add_patch(plt.Rectangle((j, i), 0.94, 0.94, color=color, linewidth=0))
            if cm[i][j]:
                ax.text(j + 0.47, i + 0.5, str(cm[i][j]), ha="center", va="center", fontsize=8,
                        color=SURFACE if v > 0.55 else INK)
    ax.set_xlim(0, len(preds))
    ax.set_ylim(len(labels), 0)
    ax.set_xticks([j + 0.47 for j in range(len(preds))], [SHORT.get(p, p) for p in preds], rotation=35, ha="right")
    ax.set_yticks([i + 0.47 for i in range(len(labels))], [SHORT[t] for t in labels])
    style(ax, f"First diagnosis vs. ground truth (n={len(rows)}, macro-F1 {macro:.2f})", "diagnosed cause", "true cause")
    ax.grid(False)
    save(fig, fig_name)


def rq2_ablation(main_rows: List[dict], abl: List[dict], md: List[str], summary: dict) -> None:
    md.append("## RQ2/RQ4 - Ablations and baseline policies (same episodes, one switch flipped)\n")
    seeds = {r["seed"] for r in abl}
    allrows = [r for r in main_rows if r["seed"] in seeds] + abl
    by: Dict[str, List[dict]] = defaultdict(list)
    for r in allrows:
        by[r["config"]].append(r)
    body, summ = [], {}
    order = ["full"] + [c for c in by if c != "full"]
    for c in order:
        g = by[c]
        benign = [r for r in g if not r["is_attack"]]
        attacks = [r for r in g if r["is_attack"]]
        gw = [r for r in g if r["fault"] == "GATEWAY"]
        body.append([c, len(g), rate(g, lambda r: r["detected"] or r.get("neutralised")), rate(g, handled),
                     rate(g, lambda r: r["outcome"] == "RECOVERED" or r.get("neutralised")),
                     rate(g, "false_recovery"), rate(benign, "false_quarantine"),
                     rate(attacks, lambda r: not r.get("neutralised")
                          and not any(a == "QUARANTINE" for a in r["actions"].split("|"))),
                     f"{mean([r['exposure_ticks'] for r in g]):.1f}", f"{mean([r['outage_ticks'] for r in g]):.1f}",
                     f"{mean([r['child_isolations'] for r in gw]):.2f}" if gw else "-",
                     f"{mean([r['other_incidents'] for r in g]):.2f}",
                     f"{mean([r.get('genuine_dropped', 0) for r in g]):.1f}"])
        summ[c] = {"final_correct": round(mean([float(handled(r)) for r in g]), 4),
                   "exposure": round(mean([r["exposure_ticks"] for r in g]), 2),
                   "outage": round(mean([r["outage_ticks"] for r in g]), 2),
                   "false_quarantine": round(mean([float(r["false_quarantine"]) for r in benign]), 4) if benign else None,
                   "false_recovery": round(mean([float(r["false_recovery"]) for r in g]), 4)}
    summary["ablation"] = summ
    md.append(table(["Configuration", "n", "Detected %", "Final diagnosis correct %", "Verified recovery %",
                     "False recovery %", "False quarantine % (benign)", "Attack never quarantined %",
                     "Exposure", "Outage", "Gateway child isolations", "Collateral incidents",
                     "Genuine msgs dropped"], body))
    md.append("\nExposure/outage are mean ticks per episode. An attack whose every forged message was rejected at "
              "ingestion (MAC) never reached the data and counts as detected, correctly handled and recovered. "
              "'Attack never quarantined' excludes those. 'Genuine msgs dropped' = the device's OWN messages lost to "
              "the firewall (collateral of blocking the whole device instead of only the impostor).\n")

    fig, axes = plt.subplots(1, 2, figsize=(9.6, 4.2))
    names = order
    for ax, key, title in [(axes[0], "exposure", "Wrong readings accepted as trusted"),
                           (axes[1], "outage", "Ticks with no trusted data and no standby")]:
        vals = [summ[c][key] for c in names]
        ax.barh(range(len(names)), vals, color=[SERIES[0] if c != "full" else SERIES[1] for c in names],
                height=0.7, edgecolor=SURFACE, linewidth=2)
        for i, v in enumerate(vals):
            ax.text(v, i, f" {v:.1f}", va="center", fontsize=7, color=INK2)
        ax.set_yticks(range(len(names)), names)
        ax.invert_yaxis()
        style(ax, title, "mean ticks per episode")
        ax.grid(axis="y", visible=False)
    save(fig, "fig_ablation_harm")


def rq3_ramp(rows: List[dict], md: List[str], summary: dict) -> None:
    md.append("## RQ3 - Where drift-shaped tampering becomes indistinguishable from drift\n")
    slopes = sorted({float(r["slope"]) for r in rows})
    series = [("DRIFT", "", False, "benign drift (P diagnosed drift)")]
    for att in ("fabricate", "inpath", "rogue", "compromised"):
        for mac in (False, True):
            series.append(("TAMPER_RAMP", att, mac, f"{att}{' +MAC' if mac else ''}"))
    curve: Dict[str, List[Tuple[float, float, int]]] = {}
    body = []
    for fault, att, mac, label in series:
        pts = []
        for s in slopes:
            g = [r for r in rows if r["fault"] == fault and r["attacker"] == att and bool(r["auth"]) == mac
                 and float(r["slope"]) == s]
            if not g:
                continue
            if fault == "DRIFT":
                k = sum(r["first_cause"] == "SENSOR_DRIFT" for r in g)
            else:
                # attack recognised on first diagnosis, or never reached the data at all (blocked by MAC)
                k = sum(r["first_cause"] in ATTACK_CAUSES or not r["detected"] and r["exposure_ticks"] == 0 for r in g)
            pts.append((s, k / len(g), len(g)))
        curve[label] = pts
        eventual = [r for r in rows if r["fault"] == fault and r["attacker"] == att and bool(r["auth"]) == mac]
        if fault == "DRIFT":
            ev = rate(eventual, lambda r: r["outcome"] == "RECOVERED")
        else:
            ev = rate(eventual, lambda r: "QUARANTINE" in r["actions"].split("|") or (not r["detected"] and r["exposure_ticks"] == 0))
        body.append([label] + [f"{100 * p:.0f}" for _, p, _ in pts] + [ev, f"{mean([r['exposure_ticks'] for r in eventual]):.1f}"])
    md.append(table(["Series"] + [f"slope {s:g}" for s in slopes] + ["Eventually contained %", "Mean exposure"], body))
    md.append("\nCells: % of episodes whose FIRST diagnosis was right (attack recognised as an attack - or never "
              "reached the data because MAC dropped it - / drift recognised as drift). Slope is in device-noise "
              "sigma per reading. 'Eventually contained' = the closed loop ended in quarantine (attacks) or verified "
              "recovery (drift), counting escalations after a failed first action.\n")
    summary["rq3"] = {k: [(s, round(p, 3)) for s, p, _ in v] for k, v in curve.items()}

    # colour and marker follow the entity, identically in both panels
    entity = {"": 0, "fabricate": 1, "inpath": 2, "rogue": 3, "compromised": 4}
    names = {"": "benign drift", "fabricate": "fabricate", "inpath": "in-path", "rogue": "rogue publisher",
             "compromised": "compromised"}
    fig, axes = plt.subplots(1, 2, figsize=(10.8, 4.3), sharey=True)
    for ax, mac in ((axes[0], False), (axes[1], True)):
        groups: Dict[tuple, List[str]] = {}
        for (fault, att, m, label) in series:
            if fault == "TAMPER_RAMP" and m != mac:
                continue
            key = tuple(round(100 * p, 1) for _, p, _ in curve[label])
            groups.setdefault(key, []).append(att)      # identical curves are drawn once, labelled together
        labels_at = []
        for key, atts in groups.items():
            i = max(entity[a] for a in atts)   # a merged line keeps one fixed colour in both panels
            ax.plot(slopes[:len(key)], key, color=SERIES[i], marker=MARKERS[i], markersize=5, linewidth=2,
                    markeredgecolor=SURFACE, markeredgewidth=1)
            text = " = ".join(names[a] for a in atts)
            if mac and len(atts) > 1:
                text += " (forgeries rejected)"
            labels_at.append([key[-1], text])
        labels_at.sort()
        for j in range(1, len(labels_at)):              # keep direct labels at least 7 points apart
            labels_at[j][0] = max(labels_at[j][0], labels_at[j - 1][0] + 7)
        for y, text in labels_at:
            ax.annotate(text, (slopes[-1], y), xytext=(8, 0), textcoords="offset points", fontsize=7.5,
                        color=INK2, va="center", annotation_clip=False)
        style(ax, "Without message authentication" if not mac else "With per-device MAC",
              "ramp slope (noise sigma per reading)", "% told apart correctly on first diagnosis" if not mac else "")
        ax.set_ylim(-3, 106)
        ax.set_xlim(0, max(slopes) * 1.55)
        ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    save(fig, "fig_separability_curve")


def rq_env(rows: List[dict], md: List[str], summary: dict) -> None:
    md.append("## Zone-wide physical events (heatwave +6 degC) - consensus vs. per-device baselines\n")
    body, summ = [], {}
    for c in ("full", "no_consensus"):
        quiet = [r for r in rows if r["config"] == c and r["fault"] == "NONE"]
        drift = [r for r in rows if r["config"] == c and r["fault"] == "DRIFT"]
        fa = mean([r["other_incidents"] + (1 if r["detected"] else 0) for r in quiet])
        body.append([c, len(quiet), f"{fa:.2f}", rate(drift, "correct_first"), med([r["mttd"] for r in drift])])
        summ[c] = {"false_incidents_per_heatwave": round(fa, 3),
                   "drift_found_during_heatwave": round(mean([float(r["correct_first"]) for r in drift]), 4)}
    summary["env"] = summ
    md.append(table(["Configuration", "n", "False incidents per heatwave", "Concurrent drift diagnosed correctly %",
                     "Drift MTTD s"], body))
    md.append("")


def rq5_trust(rows: List[dict], md: List[str], summary: dict) -> None:
    md.append("## RQ5 - Trust models under an ON-OFF attacker (4 readings bad, 26 good, repeating)\n")
    body, summ = [], {}
    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    for idx, model in enumerate(("ema", "asym", "beta")):
        g = [r for r in rows if r["config"] == model]
        if not g:
            continue
        traces = [r["trust_trace"] for r in g if r.get("trust_trace")]
        n = min(len(t) for t in traces)
        avg = [sum(t[i] for t in traces) / len(traces) for i in range(n)]
        xs = [i * 4 * 1.5 for i in range(n)]
        ax.plot(xs, avg, color=SERIES[idx], linewidth=2, marker=MARKERS[idx], markevery=max(1, n // 10),
                markersize=5, markeredgecolor=SURFACE)
        ax.annotate(model, (xs[-1], avg[-1]), xytext=(6, 0), textcoords="offset points", fontsize=8, color=INK2, va="center")
        late = avg[len(avg) // 2:]
        body.append([model, len(g), f"{mean(late):.3f}", f"{mean([r['min_trust'] for r in g]):.3f}",
                     f"{mean([r['reincidents'] + 1 for r in g if r['detected']]):.1f}",
                     f"{mean([r['exposure_ticks'] for r in g]):.1f}"])
        summ[model] = {"late_mean_trust": round(mean(late), 4), "exposure": round(mean([r["exposure_ticks"] for r in g]), 2)}
    style(ax, "Mean trust of an ON-OFF attacker over time", "time since attack start (s)", "trust score")
    ax.set_ylim(0, 1.02)
    save(fig, "fig_trust_onoff")
    summary["trust"] = summ
    md.append(table(["Trust model", "n", "Mean trust (2nd half)", "Min trust", "Incidents per episode",
                     "Exposure (ticks)"], body))
    md.append("\nLower trust for a device that keeps attacking is better; exposure counts wrong readings accepted.\n")


def rq_quiet(rows: List[dict], md: List[str], summary: dict) -> None:
    md.append("## False alarms in fault-free operation\n")
    body, summ = [], {}
    for c in ("full", "no_consensus"):
        g = [r for r in rows if r["config"] == c]
        if not g:
            continue
        devices = 24
        hours = sum(1200 * 1.5 / 3600 for _ in g) * devices
        n_inc = sum(r["other_incidents"] + (1 if r["detected"] else 0) for r in g)
        body.append([c, len(g), f"{hours:.1f}", n_inc, f"{n_inc / hours:.3f}"])
        summ[c] = round(n_inc / hours, 4)
    summary["false_alarms_per_device_hour"] = summ
    md.append(table(["Configuration", "runs", "device-hours", "incidents", "incidents per device-hour"], body))
    md.append("\n(simulated time; 24 devices per run)\n")


def learned_baseline(rows: List[dict], md: List[str], summary: dict) -> None:
    """Accuracy-vs-explainability: a decision tree and a random forest trained on the SAME evidence features."""
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.tree import DecisionTreeClassifier
    except ImportError:
        return
    data = [r for r in rows if r["detected"] and r["evidence"]]
    keys = sorted({k for r in data for k in r["evidence"]})
    X = [[float(r["evidence"].get(k, -1.0)) for k in keys] for r in data]
    y = [r["expected"] for r in data]
    seeds = sorted({r["seed"] for r in data})
    cut = seeds[len(seeds) // 2]
    tr = [i for i, r in enumerate(data) if r["seed"] < cut]
    te = [i for i, r in enumerate(data) if r["seed"] >= cut]
    if not tr or not te:
        return
    out = {"rule_arbitration": sum(data[i]["first_cause"] == y[i] for i in te) / len(te)}
    for name, model in (("decision_tree_depth4", DecisionTreeClassifier(max_depth=4, random_state=0)),
                        ("random_forest_200", RandomForestClassifier(n_estimators=200, random_state=0))):
        model.fit([X[i] for i in tr], [y[i] for i in tr])
        pred = model.predict([X[i] for i in te])
        out[name] = sum(p == y[i] for p, i in zip(pred, te)) / len(te)
    summary["learned_baseline"] = {k: round(v, 4) for k, v in out.items()}
    md.append("## Rule arbitration vs. learned classifiers on the same evidence (train seeds < "
              f"{cut}, test seeds >= {cut}, n_test={len(te)})\n")
    md.append(table(["Method", "Test accuracy %", "Explainable?"],
                    [["SentinelTwin evidence arbitration (no training)", f"{100 * out['rule_arbitration']:.1f}", "yes - every point listed"],
                     ["Decision tree, depth 4", f"{100 * out['decision_tree_depth4']:.1f}", "partly (paths)"],
                     ["Random forest, 200 trees", f"{100 * out['random_forest_200']:.1f}", "no"]]))
    md.append("\nThe learned models are trained on simulator ground truth that a real deployment would not have.\n")


def main() -> None:
    md = ["# SentinelTwin - evaluation results\n",
          "Generated by `python -m experiments.report` from `results/raw/*.jsonl` "
          "(produced by `python -m experiments.run_all`). Every number below is reproducible from the seeds.\n"]
    summary: dict = {}
    main_rows = load("main")
    if main_rows:
        rq1_main(main_rows, md, summary)
        learned_baseline(main_rows, md, summary)
    abl = load("ablation")
    if abl and main_rows:
        rq2_ablation(main_rows, abl, md, summary)
    ramp = load("ramp")
    if ramp:
        rq3_ramp(ramp, md, summary)
    env = load("env")
    if env:
        rq_env(env, md, summary)
    tr = load("trust")
    if tr:
        rq5_trust(tr, md, summary)
    q = load("quiet")
    if q:
        rq_quiet(q, md, summary)
    intel = load("intel")
    if intel:
        rq1_main(intel, md, summary, key="intel", fig_name="fig_confusion_matrix_intel",
                 title="## Tier B - the same evaluation on REAL indoor physics (Intel Berkeley Lab traces replayed)\n")
        quiet_i = [r for r in intel if r["fault"] == "NONE"]
        if quiet_i:
            n = sum(r["other_incidents"] + (1 if r["detected"] else 0) for r in quiet_i)
            hours = len(quiet_i) * 24 * (240 * 1.5 / 3600)
            summary["intel"]["false_alarms_per_device_hour"] = round(n / hours, 4)
            md.append(f"Fault-free real-trace runs: {n} incidents in {hours:.0f} device-hours "
                      f"({n / hours:.3f} per device-hour).\n")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"wrote {OUT / 'RESULTS.md'} and {len(list(FIGS.glob('*.png')))} figures")


if __name__ == "__main__":
    main()
