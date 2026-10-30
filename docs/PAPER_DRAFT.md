# SentinelTwin: Telling a Broken IoT Sensor from a Lying One — Explainable Digital-Twin Diagnosis with Cost-Aware, Verified Self-Healing

*Draft for an IEEE conference submission (target: IEEE INDICON / COMSNETS / WF-IoT; CNSM or NOMS short paper).
About 6 pages in IEEEtran two-column format. Every number below comes from `results/RESULTS.md` and
`results/summary.json`, which can be regenerated from seeds. Items marked **[check]** need a bibliographic or
venue check before submission. Authors: fill in. If the venue requires it, disclose AI assistance in line with its policy.*

---

## Abstract

IoT self-healing systems usually treat an anomaly as something to fix, without asking whether the device is
*broken* or *lying*. A drifting sensor and a slow false-data injection produce the same signature, but the
correct responses are opposite: recalibration absorbs an attacker's offset into the calibration, and quarantine
takes a merely faulty device offline for nothing. We present SentinelTwin, a digital-twin framework that
(i) separates benign hardware, network, gateway and drift faults from tampering, drift-shaped false-data
injection, flooding and identity spoofing on the same telemetry, using explainable evidence arbitration over a
zone consensus of physically co-located sensors; (ii) chooses a response by minimising expected cost over the
resulting cause probabilities, including a containment action for ambiguous cases; and (iii) verifies every action
afterwards against the device's last verified calibration, escalating when verification fails. Across 5,390
seeded episodes, including replays of real indoor physics from the Intel Berkeley Lab deployment, SentinelTwin
diagnoses the first cause correctly in 96.1% of simulated and 95.2% of real-trace episodes, reaching 98.2% and
98.5% after closed-loop escalation. It outperforms a decision tree and a random forest trained on the same evidence
(95.8% vs. 89.7% and 87.9%). Zone consensus cuts false alarms from 5.25 to 0.017 per device-hour, and expected-cost
response cuts false quarantines of benign faults from 20.0% to 2.2%. Without post-action verification, 50.9% of
recoveries are false. We also measure an honest boundary: a compromised device that slowly ramps its true readings is
indistinguishable from drift on first diagnosis, yet 92.1% of such attacks are still contained because the loop
notices that recalibration did not hold. We release the framework and a labelled trace generator in which faults,
drift, environment changes and attacks co-occur on the same telemetry.

**Index Terms** — Internet of Things, digital twin, self-healing, fault diagnosis, false data injection,
explainability, trust management.

---

## I. Introduction

Low-cost IoT deployments fail in ordinary ways (stuck sensors, failing links, slowly drifting calibration) and are
attacked in ways designed to look ordinary. Digital twins, live software mirrors of each device, have become a
common basis for IoT anomaly detection and intrusion detection [5], [6], [35]. Most of this work, however, stops at
a detection or classification accuracy and treats "anomalous" as the end of the story [12], [36].

Three questions remain open in the literature we reviewed (Section II):

1. **Fault or attack?** Work on distinguishing faults from attacks lives mostly in control theory [31]–[33]. Attacks
   shaped like gradual drift are the hardest to detect [34], and distinguishing a replay from sensor bias is called an
   open problem [33]. IoT and digital-twin platforms that do separate the two typically treat "erroneous data or
   attack" as one class [3].
2. **What to do under uncertainty?** Explanations in IoT intrusion detection are rarely tied to a response [40], [41],
   and response actions are usually chosen for the single most likely cause.
3. **Did the fix work?** Validation is "often not considered yet in recovery and mitigation scenarios" [15]. The
   digital-twin network reference architecture tests corrections *before* deploying them [16], not afterwards. Reported
   recovery rates are defined inconsistently, and some are targets rather than measurements [56].

SentinelTwin addresses all three on low-cost, explainable statistics. Its contributions are:

- **C1 — Zone consensus for fault/attack/environment separation.** Co-located devices measure the same physical
  quantities; a leave-one-out, trust-weighted median turns every reading into a residual against the room. Both slow
  and sudden changes are judged on that residual, so a room-wide change cancels out while a faulty or forged sensor
  stands out.
- **C2 — Evidence arbitration with an explicit threat model.** Each diagnosis is a probability per cause plus the
  human-readable evidence that produced it. Drift-shaped injection is separated from drift using a physical
  aging-rate prior, co-movement with the room's physics, and transport provenance (sequence numbers, publisher
  fingerprint, optional per-device MAC).
- **C3 — Expected-cost response and post-action verification.** Actions minimise expected cost over the cause
  probabilities, including a `DISTRUST_DATA` containment action. Every action is then verified against the device's
  last *verified* offset, so re-learning cannot launder an attacker's offset; failed verification triggers escalation.
- **C4 — Measured cost of misdiagnosis.** Beyond accuracy, we measure false quarantines, false recoveries, wrong
  readings accepted as trusted, outage, collateral drops of genuine messages, and alarm storms, across 15 ablated or
  baseline configurations.
- **C5 — Open artefacts.** The framework, a reproducible evaluation harness (5,390 seeded episodes), a hardware
  path (ESP32 + DHT22 over MQTT) with a scripted fault campaign, and a generator for a labelled trace in which
  benign faults, drift, environment changes and attacks co-occur, which to our knowledge no public IoT dataset
  provides (Section II-D).

---

## II. Related Work

**A. Digital twins for IoT fault management and security.** Twin-based anomaly detection compares readings with twin
predictions [5], [6]; industrial work trains fault classifiers on twin-generated data [8], [9] and replaces faulty
sensors with learned virtual sensors [7], [23]. Digital-twin intrusion detection is dominated by simulation-based
classifiers [36], [37]. Alanezi and Mishra host per-node twins on a fog server and detect misbehaving nodes with an MLP,
treating erroneous data and attacks as one class [3]. El-Hajj couples an Eclipse Ditto twin with Snort on a
Raspberry Pi testbed: floods are caught, scans barely, and resource usage stays elevated afterwards, which the
author notes "suggests the need for better recovery mechanisms" [4]. Dutta et al. chain a contrastive anomaly detector
to a causal root-cause stage and report shorter diagnosis time against IDS baselines in simulation [1]; the
contribution of the stage split itself is not isolated, which our `no_security_layer` ablation tests directly.
Rodrigues et al. show that simple μ+3σ packet-rate thresholds catch DoS on twin traffic [2]; we compare that rule
with a learned-cadence multiple.

**B. Self-healing and verification.** MAPE-K style self-healing loops for IoT are surveyed in [14]; LLM-based
autonomic agents are emerging [13], [15], [26]–[29], but hallucinated or unvalidated actions are a recognised risk
[15], [29], [30]. The IRTF digital-twin network draft [16] and ITU-T Y.3090 [17] describe testing changes in the twin
before deployment; SentinelTwin adds verification after the action.

**C. Drift, calibration, trust and explanation.** In-situ calibration is mature [19]–[22] but needs dense,
correlated neighbours and lacks benchmarks [19], [20]. Trust management in IoT commonly uses EMA or reputation
models known to be vulnerable to on-off behaviour [38], [39]. Post-hoc SHAP or LIME explanations are costly, unstable
and rarely tied to a response [40], [41].

**D. Datasets.** Major IoT security datasets are flow-level and attack-only [43]–[47]; TON_IoT telemetry carries
sensor values with attack labels but no benign faults [42]; fault benchmarks have no adversarial class [48]. We found
no public dataset that labels benign faults, drift and attacks on the same telemetry, so we evaluate in three tiers
(Section V) and release a generator for such a trace. **[check before submission:** power-system datasets that label
natural events separately from attacks; the EWSN 2023 concept-drift dataset**]**

---

## III. System Design

**Overview.** One tick (1.5 s) runs Monitor → Detect → Security layer → Diagnose → Respond → Recover → Verify over
a registry of device twins. Simulated devices and real devices (MQTT) enter through a single ingestion boundary, so
every transport-level check applies identically to both.

**A. Ingestion and security layer.** For each message, in order: firewall (device-scoped, or publisher-scoped when
a distinct impostor fingerprint is known) → isolation → rate check → identity check → provenance → push into the
twin. The rate check learns each device's cadence from non-burst traffic and flags a window rate above 5× that
cadence (alternative: μ+3σ [2]). Identity claims (`device_type`, `zone`) that conflict with registration are blocked.
Provenance records sequence regressions or jumps, publisher-fingerprint mismatches, and failed per-device HMAC-SHA256
over the exact bytes sent. A fast path firewalls a device immediately when two or more sensed metrics jump past
z = 3.2 in one reading. Blocks escalate 30 → 60 → 120 → 240 s, capped at 300 s.

**B. Zone consensus and detection.** For each physical quantity (temperature, humidity), the consensus for device
*d* is the trust-weighted median of fresh readings from *other* healthy, trusted devices in its zone (at least two
peers). The residual *r* = reading − consensus is compared with the device's frozen calibration offset and with its last
*verified* offset (whichever is larger), giving a residual z-score on a 3-reading mean. Sudden jumps are also judged
on the residual series when peers exist. Metrics without peers use rolling and frozen baselines with a running noise
estimate. Stuck values (8 identical readings of a noisy metric) and dropout rate complete the detector. A device
becomes SUSPECT at a combined score of 0.6 (≈ z 5).

**C. Evidence arbitration.** Each hypothesis starts from a prior (drift-shaped attacks −0.7 log-odds relative to
drift) and receives signed points from named evidence. Examples: link quality and the share of peers behind the same
gateway with link symptoms (network vs. upstream gateway); a single vs. multiple sensed metrics jumping (hardware vs.
tampering); a slow residual departure (drift vs. stealthy injection), refined by the residual slope against a physical
aging bound, co-movement of detrended device and consensus series, provenance anomalies and MAC failures. A softmax
gives cause probabilities, and the list of evidence lines is the explanation shown to operators (Fig. 1).
Co-movement threshold and weight were chosen on development seeds only (Section V).

**D. Expected-cost response.** Let *P(c | e)* be the cause probabilities and *C[a][c]* a readable 0–10 cost table
(harm to data integrity, availability and operator effort). The action is
*a\* = argmin_a Σ_c P(c | e) C[a][c] + π_a*, where *π_a* penalises actions that would leave a zone without standby
coverage (a pre-action check on the twin). Actions: OBSERVE, RECALIBRATE, ACTIVATE_BACKUP (with a repair ticket),
REROUTE, GATEWAY_FAILOVER, QUARANTINE (with credential rotation) and DISTRUST_DATA. DISTRUST_DATA keeps the device
online but excludes its data from the consensus and from consumers, covers the service with a standby, and re-diagnoses
each reading until a cause exceeds 0.8 probability (or 25 readings pass).

**E. Verification and escalation.** After an action, the device must produce 4 clean readings (6 after a security
action, counted only after the firewall block expires): low anomaly score, a residual within 3.5 σ of its last
*verified* offset, a healthy link and no provenance anomalies. Six failed checks mark the action as failed; the
device is re-diagnosed on fresh evidence and the next-best action that has not already failed is taken. After three
escalations the incident goes to an operator. Incidents carry timestamps for detection, diagnosis, containment and
verified recovery.

**F. Trust.** Three interchangeable models: symmetric EMA, asymmetric EMA (fast loss, slow gain, and a ceiling lowered
by each confirmed attack), and beta reputation with forgetting. Trust weights each device's vote in the consensus.

---

## IV. Threat and Fault Model

Benign faults are hardware spikes, stuck values, dropout, link degradation, gateway failure and drift, chosen to match
common sensor fault taxonomies [51]. Real zone-wide environment changes (heatwaves) are *not* faults. Attackers are:
abrupt multi-metric tampering; an on-off attacker; DoS flooding; identity spoofing by an impostor publisher; and
drift-shaped false-data injection (stealthy FDI) with four capabilities:

| Attacker | Sees true signal | Valid MAC | Transport footprint |
|---|---|---|---|
| fabricate (in-path) | no | no | none |
| in-path modifier | yes | no | none |
| rogue publisher | no | no | second sequence space and fingerprint |
| compromised device | yes | yes | none |

A compromised device that adds a slow ramp to its true readings is, by construction, observationally equivalent to
drift except for its rate. We do not claim to detect it on first diagnosis; we measure where that becomes possible
and what the closed loop does in the meantime. Reconnaissance scans and attacks on the broker or server are out of
scope.

---

## V. Evaluation Methodology

**Testbed.** Three zones, each with a temperature sensor, a humidity sensor, a motion sensor and a gateway, plus one
standby per type; a fourth zone hosts standbys for real hardware (24 devices). Each zone's environment has a diurnal
cycle, an Ornstein–Uhlenbeck random walk and optional heatwaves. Devices measure it with DHT22-scale noise.
Actions only fix what they would fix physically: recalibration does not stop an attacker, quarantine does not repair a
drifting sensor, and repairs take 60 s.

**Three tiers.** *Tier A (simulation)*: 11 fault and attack classes × 30 seeds (RQ1), 15 configurations × 15 seeds
(RQ2/RQ4), an attacker × slope × MAC sweep (RQ3), heatwaves, on-off trust runs (RQ5) and fault-free runs.
*Tier B (real physics)*: the same 11 classes plus fault-free runs, with each zone's environment replayed from a real
group of 10 neighbouring Intel Berkeley Lab motes (per-epoch median, cleaned) **[cite Intel Lab dataset — check]**.
Each seed replays a different window; traces are replayed about 20× faster than real time.
*Tier C (hardware, optional)*: ESP32 + DHT22 firmware with a scripted fault campaign over MQTT
(`tools/hw_campaign.py`). **[Results to be added if the campaign is run; otherwise list it as future work.]**

**Protocol.** Faults are injected after a 60-tick warm-up and observed for 240 ticks. Co-movement parameters were
selected on development seeds 1000–1019 (`experiments/tune.py`), never on the 30 evaluation seeds. Rates are reported
with 95% Wilson intervals; times as median [IQR] in simulated seconds.

**Metrics.** Detection rate and MTTD (onset → SUSPECT); first and final diagnosis accuracy, macro-F1 and confusion
matrix; verified recovery rate and MTTR (detection → verified healthy); *false recovery* (declared healthy while the
fault is still active); *false quarantine* of benign faults; *exposure* (readings more than 5σ wrong yet accepted as
trusted); *outage* (no trusted data and no standby covering); collateral incidents and drops of genuine messages;
gateway alarm-storm isolations.

**Baselines and ablations.** Rolling-only detection; no zone consensus; no security layer (single-stage);
no provenance; no co-movement; no rate prior; argmax policy (fixed action per most likely cause); naive restart on any
anomaly; detect-only (no healing); no verification (open loop); permanent blocking; device-scoped blocking; μ+3σ rate
rule [2]; with per-device MAC; and decision-tree and random-forest classifiers trained on the same evidence vectors
(train seeds < 15, test seeds ≥ 15).

---

## VI. Results

**RQ1 — Diagnosis and verified recovery (Table I, Fig. 2).** Over 330 simulated episodes the first diagnosis is correct
in 96.1% (macro-F1 0.968), 98.2% after escalation, and 100% of incidents reach verified recovery. Hardware, network,
gateway, abrupt tampering, flooding and spoofing are diagnosed correctly in every episode. The residual errors are
drift vs. stealthy FDI (4 drifts first called FDI) and slow ramps first read as a single-sensor hardware fault
(7 of 60), which escalation later corrects. MTTD is 0 s for abrupt faults and 49–57 s (median) for drift and ramps.
On real Intel Lab physics, first-diagnosis accuracy is 95.2% (macro-F1 0.957), final 98.5%, with 0.028 false incidents
per device-hour in fault-free runs.

**Table I (excerpt).** Per-class results, simulation (n = 30 each; see `results/RESULTS.md` for all columns and CIs).

| Fault | 1st correct | Final correct | Verified recovery | MTTR (s) | False quarantine |
|---|---|---|---|---|---|
| Hardware / Stuck / Dropout | 100 / 100 / 100 | 100 | 100 | 73.5 | 0 / 3.3 / 0 |
| Network / Gateway | 100 / 100 | 100 | 100 | 97.5 / 73.5 | 0 |
| Drift | 83.3 | 93.3 | 100 | 13.5 | 6.7 |
| Tampering / Flood / Spoof | 100 | 100 | 100 | 45 / 45 / 12 | 0 |
| Stealth FDI (fabricate) | 80.0 | 93.3 | 100 | 126 | 0 |
| Stealth FDI (rogue) | 93.3 | 93.3 | 100 | 15 | 0 |

**Explainable vs. learned.** On held-out seeds, evidence arbitration (no training) reaches 95.8% against 89.7% for a
depth-4 decision tree and 87.9% for a random forest on the same features. The learned models also rely on simulator
ground truth that a deployment would not have.

**RQ2 — Zone consensus.** Removing consensus raises false alarms from 0.017 to 5.25 per device-hour, lowers final
accuracy from 99.4% to 56.4%, and causes 12.3 collateral incidents per episode. During a real zone-wide heatwave (+6 °C)
consensus gives 0.03 false incidents against 17.2 without it, and still finds a sensor drifting *during* the heatwave in
96.7% of runs (6.7% without).

**RQ3 — Separability of drift-shaped injection (Fig. 3).** Without MAC, rogue publishers are recognised on first
diagnosis in 83–100% of runs at every slope, via their transport footprint. Fabricated ramps are recognised in 50–83%,
via loss of co-movement with the room. In-path and compromised ramps of the true signal are recognised in only 10–27%
below 0.4 σ per reading, rising to 53–70% above the physical aging bound. With a per-device MAC, every fabricated,
in-path and rogue forgery is rejected at ingestion (zero exposure). Only the compromised device remains; it is first
diagnosed as drift, recalibration fails verification, and 92.1% of such attacks end in quarantine. Benign drift faster
than the aging bound is, symmetrically, increasingly called an attack (17–37% recognised as drift above 0.6 σ).

**RQ4 — Response policy and verification (Table II).** With identical diagnoses, choosing the most likely cause's
fixed action quarantines 20.0% of benign faults; expected-cost response quarantines 2.2%. Naive restart leaves 20.6%
false recoveries and quarantines no attack. Without post-action verification, 50.9% of recoveries are false, final
accuracy falls to 52.7%, and a failed gateway's children are re-homed onto the dead gateway, producing 64.9 child
isolations per gateway failure against 0. Permanent blocking reduces verified recovery to 70.9% and multiplies genuine
message drops eightfold (62.5 vs. 7.8). Removing the security layer lowers final accuracy from 99.4% to 90.3%, and
removing provenance to 92.7%. The μ+3σ rule also labels a second (rogue) publisher's doubled rate as a flood (90.3%).

**Table II (excerpt).** Ablations (n = 165 each).

| Configuration | Final correct | False recovery | False quarantine (benign) | Exposure | Outage |
|---|---|---|---|---|---|
| **SentinelTwin (full)** | **99.4** | **0.0** | **2.2** | 5.4 | 0.6 |
| no zone consensus | 56.4 | 0.0 | 8.9 | 8.2 | 0.9 |
| rolling-only detection | 72.7 | 0.0 | 0.0 | 59.9 | 0.5 |
| no security layer | 90.3 | 0.0 | 2.2 | 5.4 | 0.6 |
| argmax policy | 96.4 | 0.0 | 20.0 | 5.0 | 1.0 |
| naive restart | 80.0 | 20.6 | 0.0 | 15.0 | 4.6 |
| no healing | 67.3 | 18.2 | 0.0 | 20.6 | 60.2 |
| no verification | 52.7 | 50.9 | 17.8 | 29.1 | 20.6 |
| with per-device MAC | 99.4 | 0.0 | 2.2 | 1.5 | 1.0 |

**RQ5 — Trust under on-off attack.** Against a persistent attacker (4 bad readings in every 30), asymmetric trust holds
the device at 0.06 in the second half of the run, against 0.21 for symmetric EMA and 0.28 for beta reputation. In this
setup the trust model did not change exposure (11.1 readings), because the security layer catches each on-phase
directly; the benefit is in consensus weighting and repeat-offender priors.

---

## VII. Discussion and Limitations

- **The compromised-device boundary is fundamental, not an implementation gap.** Telemetry alone cannot separate a
  slow ramp added to true readings from aging. The useful system property is that verification catches the failed
  recalibration; the cost is exposure before containment (42 readings on average).
- **The co-movement cue trades drift accuracy for fabrication detection.** Disabling it raises final accuracy to 100%
  in Table II but weakens detection of fabricated ramps (Fig. 3). On real traces, 23% of benign drifts are first
  quarantined, then recovered by escalation.
- **Simulation and replay.** Physics are simulated (Tier A) or replayed about 20× faster than real time (Tier B); timings are in
  simulated seconds. Tier C hardware results **[pending / future work]**.
- **Design changes informed by evaluation.** The real-trace suite exposed one flaw during development (sudden jumps judged
  on raw values, so a room-wide HVAC step looked like multi-metric tampering). It was fixed and every suite re-run.
  Co-movement parameters were tuned on separate development seeds.
- **Scope.** Consensus needs at least three co-located sensors of a quantity. Scans, broker compromise and colluding
  devices are out of scope; cost-table values are design choices, exposed for operators to change.

---

## VIII. Conclusion

SentinelTwin shows that a small set of explainable statistics, with physically co-located peers as the reference,
an expected-cost response and post-action verification, can tell broken IoT sensors from lying ones in most cases,
avoid acting rashly when it cannot, and notice when it was wrong. The measured boundary, where drift-shaped tampering by a
compromised device becomes indistinguishable from drift, and the cost of acting on misdiagnosis are, to our knowledge,
reported here for the first time for a digital-twin IoT platform. Future work: the hardware campaign, an LLM explainer
behind the deterministic guard, and trust-weighted federated learning across sites.

---

## References

*Numbering follows `reports/SentinelTwin research landscape.md`, where every entry was checked against a publisher,
PMC, arXiv, DBLP, standards-body or repository page. Before submission, renumber in citation order, complete the
author lists marked [check], and convert to IEEEtran BibTeX.*

[1] A. K. Dutta, M. Anjum, H. Min, Y. I. Daradkeh, J. T. Seo, S. Shahab, "Digital twin-assisted blockchain IoT security model using contrastive and causal learning techniques," *Scientific Reports*, vol. 16, 15732, 2026, doi:10.1038/s41598-026-47104-6.
[2] Rodrigues *et al.* [check full author list], "A data rate monitoring approach for cyberattack detection in digital twin communication," *Sensors*, vol. 25, no. 24, 7476, 2025, doi:10.3390/s25247476.
[3] K. Alanezi, S. Mishra, "An IoT architecture leveraging digital twins: compromised node detection scenario," *IEEE Systems Journal*, vol. 18, no. 2, 2024, doi:10.1109/JSYST.2024.3403500.
[4] M. El-Hajj, "Leveraging digital twins and intrusion detection systems for enhanced security in IoT-based smart city infrastructures," *Electronics*, vol. 13, no. 19, 3941, 2024, doi:10.3390/electronics13193941.
[5] Q. Xu, S. Ali, T. Yue, "Digital twin-based anomaly detection in cyber-physical systems" (ATTAIN) [check venue/year].
[6] Q. Xu, S. Ali, T. Yue, "LATTICE," arXiv:2309.15995, 2023.
[7] "Hierarchical multi-attention neural networks for sensor fault diagnosis and mitigation in digital twins," *Scientific Reports*, 2026 [check authors].
[8] "Digital twin-based automated fault diagnosis in industrial IoT applications," *CMC*, 2023 [check authors].
[9] "An efficient fault diagnosis framework for digital twins using optimized machine learning models in smart industrial control systems," *Int. J. Computational Intelligence Systems*, 2023, doi:10.1007/s44196-023-00241-6 [check authors].
[12] S. Mihai *et al.*, "Digital twins: a survey on enabling technologies, challenges, trends and future prospects," *IEEE Commun. Surveys Tuts.*, vol. 24, no. 4, pp. 2255–2291, 2022, doi:10.1109/COMST.2022.3208773.
[13] A. Zhang *et al.*, "The vision of autonomic computing: can LLMs make it a reality?" arXiv:2407.14402, 2024.
[14] "A survey on resilience in the IoT: taxonomy, classification and discussion of resilience mechanisms," arXiv:2109.02328, 2021 [check authors].
[15] Hong [check], "A comprehensive survey on LLM-based network management and operations," *Int. J. Network Management*, 2025, doi:10.1002/nem.70029.
[16] C. Zhou *et al.*, "Network digital twin: concepts and reference architecture," draft-irtf-nmrg-network-digital-twin-arch-13, IRTF NMRG, 2026.
[17] ITU-T Rec. Y.3090, "Digital twin network – requirements and architecture," 2022.
[19] F. Delaine, B. Lebental, H. Rivano, "In situ calibration algorithms for environmental sensor networks: a review," *IEEE Sensors J.*, vol. 19, no. 15, 2019, doi:10.1109/JSEN.2019.2910317.
[20] F. Delaine *et al.*, "Framework for the simulation of sensor networks aimed at evaluating in situ calibration algorithms," *Sensors*, vol. 20, no. 16, 2020.
[21] Concas *et al.*, "Low-cost outdoor air quality monitoring and sensor calibration: a survey and critical analysis," *ACM Trans. Sensor Netw.*, 2021, doi:10.1145/3446005.
[22] Waqas *et al.*, "Enhancing IoT sensors precision through sensor drift calibration with variational autoencoder," 2024 [check venue].
[23] "Digital-twin-based virtual sensors for smart swine barns," *Sensors*, vol. 25, no. 24, 7690, 2025 [check authors].
[26] Y. Chen *et al.*, "Automatic root cause analysis via large language models for cloud incidents," arXiv:2305.15778.
[27] D. Wu *et al.*, "NetLLM: adapting large language models for networking," ACM SIGCOMM, 2024.
[28] C. Wang *et al.*, "NetConfEval: can LLMs facilitate network configuration?" *Proc. ACM Netw.* (CoNEXT), 2024, doi:10.1145/3656296.
[29] "Autonomous incident resolution at hyperscale: an agentic AI architecture for network operations," arXiv:2606.09122, 2026.
[30] Kramer *et al.*, LLMs in security incident response, USENIX SOUPS, 2025 [check title].
[31] T. Roy, S. Dey, distinguishing physical faults from actuation cyberattacks, arXiv:2311.09342, 2023 [check title].
[32] Dual UIO and Luenberger observer for faults and cyber attacks in interconnected CPS, *Control Eng. Practice*, 2024 [check authors].
[33] Replay attack versus sensor bias in event-triggered CPS, *European J. Control*, 2021 [check authors].
[34] Drift-type versus spike false data injection in smart meters, *Computers*, vol. 15, no. 8, 534, 2026, doi:10.3390/computers15080534 [check authors].
[35] "Digital twin-driven intrusion detection for industrial SCADA: a cyber-physical case study," *Sensors*, vol. 25, no. 16, 4963, 2025 [check authors].
[36] "Digital twin-enabled incident detection and response: a systematic review of critical infrastructures applications," *Int. J. Inf. Security*, 2025, doi:10.1007/s10207-025-01113-0 [check authors].
[37] "Enhancing IIoT security using digital twins in Industry 5.0: a systematic literature review," *Information*, vol. 17, no. 2, 209, doi:10.3390/info17020209 [check].
[38] D. Konsta, A. Lluch Lafuente, N. Dragoni, "Trust management for Internet of Things: a systematic literature review," arXiv:2211.01712.
[39] "IoT trust and reputation: a survey and taxonomy," arXiv:2304.06119 [check authors].
[40] "Beyond detection accuracy: measuring explanation cost, stability, and utility for resource-aware IoT intrusion detection," arXiv:2608.10349, 2026.
[41] "Evaluation of explainable AI in IoT IDS under DeepFool adversarial conditions," *Sensors*, vol. 26, no. 10, 2924, 2026, doi:10.3390/s26102924 [check].
[42] A. Alsaedi, N. Moustafa, Z. Tari, A. Mahmood, A. Anwar, "TON_IoT telemetry dataset," *IEEE Access*, vol. 8, pp. 165130–165150, 2020, doi:10.1109/ACCESS.2020.3022862.
[43] E. C. P. Neto *et al.*, "CICIoT2023," *Sensors*, vol. 23, no. 13, 5941, 2023, doi:10.3390/s23135941.
[44] S. Dadkhah *et al.*, "CICIoMT2024," *Internet of Things*, vol. 28, 2024 [check DOI].
[45] M. A. Ferrag *et al.*, "Edge-IIoTset," *IEEE Access*, vol. 10, pp. 40281–40306, 2022, doi:10.1109/ACCESS.2022.3165809.
[46] H. Hindy *et al.*, "Machine learning based IoT intrusion detection system: an MQTT case study," INC 2020; arXiv:2006.15340.
[47] I. Vaccari *et al.*, "MQTTset, a new dataset for machine learning techniques on MQTT," *Sensors*, vol. 20, no. 22, 6578, 2020.
[48] T. de Bruijn *et al.*, "Benchmark datasets for fault detection and classification in sensor data," SENSORNETS, 2016.
[51] Attarha, Förster, sensor fault model review, IFIP WONS, 2024 [check title].
[56] Fault-injection three-arm self-healing evaluation, arXiv:2302.05336 [check title and authors].
[—] Intel Berkeley Research Lab sensor data (P. Bodik, W. Hong, C. Guestrin, S. Madden, M. Paskin, R. Thibaux), 2004, http://db.csail.mit.edu/labdata/labdata.html [check and add].
[—] J. O. Kephart, D. M. Chess, "The vision of autonomic computing," *IEEE Computer*, 2003 [check and add].
[—] A. Jøsang, R. Ismail, "The beta reputation system," 15th Bled eConference, 2002 [check and add].

---

### Figures to include

- **Fig. 1** — Architecture and closed loop (draw from Section III; `docs/dashboard.png` shows the live system).
- **Fig. 2** — `results/figs/fig_confusion_matrix.pdf` (and `fig_confusion_matrix_intel.pdf` for real physics).
- **Fig. 3** — `results/figs/fig_separability_curve.pdf`.
- **Fig. 4** — `results/figs/fig_ablation_harm.pdf` (exposure and outage per configuration).
- **Fig. 5 (optional)** — `results/figs/fig_trust_onoff.pdf`.
