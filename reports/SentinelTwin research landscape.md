# SentinelTwin can claim the fault-versus-attack gap

SentinelTwin's strongest defensible contribution is not any single building block. Per-device twins, z-score detection, EMA trust, MAPE-K loops, rule-based RCA and rate-based DoS detection all have clear prior art. The opening is the combination that the 2022-2026 literature keeps leaving out. That combination has three parts: **one explainable diagnoser that separates benign faults, sensor drift and attacks on the same telemetry**, **recovery that is verified after it acts**, and **an evaluation on real low-cost hardware**. To our knowledge, no public benchmark labels benign faults, drift and attacks together on the same IoT telemetry. Digital-twin intrusion detection papers are evaluated mostly in simulation or on network-flow datasets. Recovery validation is named as a missing safeguard even in LLM-based network operations. All four README citations are real papers. Two are described accurately, and two need correcting. The worst problem is the Causio-TwinChain bullet: it credits the paper's 68% and 22% figures to a stage split that the paper never isolates. The work a student team can actually finish, ranked by novelty and feasibility, has five parts: release a labelled fault, attack and drift trace from the ESP32/DHT22 rig; measure honestly how well the system separates slow, drift-shaped tampering from real drift; formalise post-action verification with phase-level recovery metrics; measure what misdiagnosis costs, meaning faults that get firewalled; and test EMA trust under on-off attacks. The right first venue is a prototype-friendly IEEE conference (WF-IoT, COMSNETS, CNSM/NOMS short or demo tracks), followed by a journal extension.

## Each building block already exists; the gap is in how they connect

### Digital twins for IoT fault management stop at classification accuracy

Twin-based anomaly detection is a mature area. It compares physical readings with twin predictions and flags the residual. Xu, Ali and Yue's ATTAIN uses a timed-automaton twin with GAN-based detection and reports an **8.39% average gain** over a non-twin approach ([Simula](https://www.simula.no/publications/anomaly-detection-digital-twin-cyber-physical-systems)). Its successor LATTICE adds curriculum learning and reports **F1 gains of 0.906–2.367%** across SWaT, WADI, BATADAL, PHM 2015 and a gas pipeline ([arXiv 2309.15995](https://arxiv.org/abs/2309.15995)). These are water-treatment and industrial datasets, not low-cost IoT hardware. In twin-based fault diagnosis, the usual design trains ML classifiers on twin-simulated data. Reported accuracies are up to **95%** with GA-SVM on triplex-pump faults ([ScienceDirect](https://www.sciencedirect.com/org/science/article/pii/S1546221823004769)) and **96.8%** with hybrid FPA–CART ([Springer](https://link.springer.com/article/10.1007/s44196-023-00241-6)). A 2025 twin for PV DC–DC converters uses exactly SentinelTwin's pattern of "residual, then classify": dynamic thresholds on the twin-versus-real gap, followed by a fault-type classifier ([PMC12300130](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12300130/)).

The closest prior art to SentinelTwin's "activate standby" action is a 2026 *Scientific Reports* paper. A hierarchical multi-attention network diagnoses sensor faults, and a multiplexer swaps the faulty sensor for a **learned virtual sensor** with no human involved ([Nature Sci. Rep.](https://www.nature.com/articles/s41598-026-42046-5)). That substitute is learned, not a physical standby, and the full text was not read for this report. One 2026 stress test of a closed-loop smart-building twin makes the methodological point SentinelTwin needs: evaluating sensor quality "only at the measurement layer can therefore miss the decision-level and outcome-level significance of sensor corruption" ([arXiv 2608.14917](https://arxiv.org/pdf/2608.14917)). Across this body of work, the reported metrics are accuracy and F1. MTTD, MTTR and verified recovery success are rarely reported. None of the twin papers found here checks that a recovery action actually restored correct behaviour.

### MAPE-K self-healing leaves verification unsolved

MAPE-K is the default framing for self-healing. The IoT resilience surveys treat self-adaptation as core to autonomous resilient IoT ([arXiv 2109.02328](https://arxiv.org/pdf/2109.02328)). The approach keeps evolving: Microsoft and Nanjing University built an LLM-based multi-agent MAPE-K loop for microservice self-management ([arXiv 2407.14402](https://arxiv.org/abs/2407.14402)). The weak spot that keeps coming up is validation. Hong's 2025 survey of LLM-based network management warns that hallucinated configurations are dangerous "when validation and recovery mechanisms are missing," and says validation is often not considered in recovery and mitigation ([Wiley, Int. J. Netw. Mgmt.](https://onlinelibrary.wiley.com/doi/full/10.1002/nem.70029)). The IRTF NMRG network-digital-twin draft describes closed-loop repair in which "corrections are tested in the twin before distribution" ([IETF datatracker](https://datatracker.ietf.org/doc/draft-irtf-nmrg-network-digital-twin-arch/)). That is a *pre*-action check. SentinelTwin's *post*-action re-check complements it, and the paper should say which of the two it does. This search did not find redundancy and standby management, or cascading failures caused by recovery actions, named as open problems in a primary IoT self-healing source. Treat both as plausible gaps to verify, not established ones.

### DT-based intrusion detection is mostly simulation feeding a classifier

Systematic reviews keep naming the same limitations of twin-based intrusion detection: high-fidelity modelling of dynamic IoT/ICS, real-time twin–physical synchronisation, and scalability ([Springer IJIS 2025](https://link.springer.com/article/10.1007/s10207-025-01113-0)). A review of 110 Industry 5.0 studies warns that "low fidelity risks flawed security decisions" ([Information 2026](https://doi.org/10.3390/info17020209)). A representative system is a DT-driven SCADA IDS that reports **F1 96.3%, FPR below 2.5% and latency under 500 ms**, all on a *simulated* water plant ([PMC12390215](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12390215/)). Across these works the twin is a monitoring mirror or a data source for an ML classifier. It is not a per-device baseline that sits in front of an explicit fault-versus-attack diagnosis and a time-boxed response. That is the niche SentinelTwin occupies.

### Fault-versus-attack disambiguation lives in control theory, not IoT platforms

The rigorous work on telling faults from attacks uses observers and residuals. Roy and Dey propose a sliding-mode unknown-input observer with a "distinguishability metric." Their argument is that countermeasures for faults and for cyberattacks "would be widely different," so the system must identify the nature of the anomaly, not just detect it ([arXiv 2311.09342](https://arxiv.org/abs/2311.09342)). A 2024 *Control Engineering Practice* paper combines dual unknown-input and Luenberger observers for interleaved faults and attacks in interconnected CPS ([ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0967066124003757)). In event-triggered CPS, separating replay attacks from sensor bias faults is described as "an open problem" ([Eur. J. Control](https://www.sciencedirect.com/science/article/abs/pii/S0947358021000844)).

The hardest case is the one SentinelTwin is most exposed to. In a 2026 smart-meter study, **drift-shaped false-data injection was detected 91.4% of the time against 98.3% for spikes**, because small accumulated deviations stay under bad-data thresholds ([Computers 2026](https://doi.org/10.3390/computers15080534)). The reverse failure exists too: in a twin-driven SCADA IDS, "minor drifts in sensor calibration" created twin–physical discrepancies, so benign drift became a false-positive source ([Sensors 2025](https://www.mdpi.com/1424-8220/25/16/4963)). This search found no IoT or DT platform paper that does explicit three-way classification of benign fault, drift and attack and evaluates it on hardware.

### Drift calibration is mature, and a frozen baseline is not a new statistic

In-situ calibration has been reviewed thoroughly. Delaine, Lebental and Rivano name the open problems as "how to improve the performance evaluation of such methods and how to enable a quantified comparison" ([HAL](https://hal.archives-ouvertes.fr/hal-02174938)). Their simulation framework paper adds that "there is a lack for a systematic benchmark of calibration algorithms" ([PMC7472635](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7472635/)). Blind calibration assumes dense, correlated neighbours and is "only useful for offset and gain calibration." Concas et al. also report that one calibration cycle holds accuracy for about a fortnight ([ACM TOSN](https://dl.acm.org/doi/fullHtml/10.1145/3446005)). Learned alternatives exist. A 2024 VAE method detects drift with KL divergence and recalibrates from reconstruction loss without manual intervention ([Greenwich GALA](https://gala.gre.ac.uk/id/eprint/49196/7/49196%20WAQAS_Enhancing_IoT_Sensors_Precision_Through_Sensor_Drift_Calibration_With_Variational_Autoencoder_(AAM)_2024.pdf)). A 2025 twin-based virtual-sensor system for swine barns reports **R² > 0.95** for CO₂ and NH₃ ([MDPI Sensors](https://www.mdpi.com/1424-8220/25/24/7690)). SentinelTwin's frozen calibration baseline is the textbook fix for the fact that a rolling window adapts to slow drift and hides it. Present it as an engineering choice made for explainability. It shares a known weakness: on its own, it cannot tell a real seasonal change from sensor drift.

### Trust, explainability, edge and FL each have well-known failure modes

Trust management is thoroughly surveyed, and its attacks are well defined: on-off, bad-mouthing, ballot-stuffing and opportunistic service ([arXiv 2211.01712](https://arxiv.org/abs/2211.01712)). A 2023 survey concludes that existing approaches are "still in the initial development stages" ([arXiv 2304.06119](https://arxiv.org/abs/2304.06119)). Static reward-and-punishment schemes, which a plain EMA effectively is, are known to let nodes exploit on-off behaviour ([TJEECS](https://journals.tubitak.gov.tr/elektrik/vol29/iss2/21)). SentinelTwin uses direct observation only, with no recommendations, so it is immune to bad-mouthing and ballot-stuffing by design. It is still exposed to on-off attacks and slow poisoning. This search found no 2022-2026 paper that evaluates EMA trust under those attacks.

Explainable IDS work is mostly post-hoc SHAP and LIME. Those explanations "do not by themselves establish causal relevance, semantic correctness, or analyst trust" ([arXiv 2608.10349](https://arxiv.org/pdf/2608.10349)), and LIME turns unstable under adversarial perturbation ([Sensors 2026](https://doi.org/10.3390/s26102924)). SentinelTwin's rules are explainable by design, and each verdict selects the response directly. That answers the critique that explanations are not tied to action. The cost is weaker generalisation to new attacks.

On the edge, an INT8 autoencoder on an ESP32-S3 fits in about **42 KB**, but its F1 fell to about **65.7%** after quantisation ([arXiv 2606.02256](https://arxiv.org/html/2606.02256v1)). An Isolation Forest was shrunk from about 800 KB to **84 KB** for ESP32 flash ([PMC9962960](https://pmc.ncbi.nlm.nih.gov/articles/PMC9962960/)). A z-score detector on an STM32 runs in about **20–40 µs** ([arXiv 2604.08581](https://arxiv.org/pdf/2604.08581)). That means SentinelTwin's statistics could run on the ESP32 itself.

Federated IDS work repeatedly names non-IID data, poisoning by malicious clients and the lack of standard benchmarks as open problems ([ar5iv 2108.00974](https://ar5iv.labs.arxiv.org/html/2108.00974); [UTP KHub](https://khub.utp.edu.my/scholars/20143/)). Edge-IIoTset was built explicitly for FL evaluation ([DOAJ](https://doaj.org/article/72942bebe6e845e3a0fbefd31f12be06)).

### LLM network agents and causal RCA argue for, not against, deterministic rules

LLM incident tooling is real and capable. Microsoft's RCACopilot predicts root-cause categories with **accuracy up to 0.766** on a year of incidents ([arXiv 2305.15778](https://arxiv.org/abs/2305.15778)). NetLLM adapts LLMs to networking tasks with double-digit gains ([arXiv 2402.02338](https://arxiv.org/abs/2402.02338)), and NetConfEval benchmarks LLM network configuration ([Crossref 10.1145/3656296](https://api.crossref.org/works/10.1145%2F3656296)). The safeguards these systems propose are deterministic safety rules, fixed output schemas, multi-model consensus and human approval. A 2026 agentic network-operations preprint, for example, checks every LLM plan against deterministic rules before running it ([arXiv 2606.09122](https://arxiv.org/pdf/2606.09122)). Autonomous LLM incident summaries also introduced factual errors in a USENIX SOUPS 2025 study ([USENIX](https://www.usenix.org/system/files/soups2025-kramer.pdf)).

Causal RCA has its own benchmark, RCAEval: **735 failure cases, 11 fault types, 15 baselines** ([arXiv 2412.17015](https://arxiv.org/abs/2412.17015)). It is microservice-only, and no IoT equivalent was found. Graph and causal-Bayesian RCA for IoT edge "rely on a pre-defined system architecture," which makes them brittle when topology changes ([PMC12987278](https://pmc.ncbi.nlm.nih.gov/articles/PMC12987278/)). Together these sources let SentinelTwin present its fixed action set and verification step as the guard layer that any future LLM or learned planner should sit behind, rather than as a primitive alternative to one.

The standards give the architecture a home. ITU-T Y.3090 (2022) defines a digital twin network for "analysing, diagnosing, emulating, and controlling the physical network" ([ITU-T](https://www.itu.int/rec/T-REC-Y.3090-202202-I/en)). The NMRG draft (revision -13, July 2026; Informational, not endorsed by the IETF) lists synchronisation and fidelity as its core challenges ([IETF datatracker](https://datatracker.ietf.org/doc/draft-irtf-nmrg-network-digital-twin-arch/)). Neither specifies per-device IoT fault-recovery procedures.

## All four README citations are real, but two bullets overstate them

All four papers were found and checked against publisher, PMC, arXiv or repository records. The problems are in how the README describes them, not whether they exist.

| README bullet | Real paper | Verdict | Problem |
|---|---|---|---|
| Causio-TwinChain: "68% cut in time-to-diagnosis, 22% fewer false positives versus combining both into one step" | Dutta, Anjum, Min, Daradkeh, Seo, Shahab, *Sci. Rep.* 16:15732, 2026 ([PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)) | **Overstated** | The figures are measured against IDS baselines, not against a one-stage version. The paper has no ablation of the stage split. 22% cannot be reproduced from its own Table 1. The evaluation is simulation only. |
| 2025 data-rate study, ~50× DoS spike | Rodrigues et al., *Sensors* 25(24):7476, 2025 ([PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12736672/)) | **Accurate, needs two caveats** | The method is a μ+3σ threshold on PPS/BPS, not "a large multiple" of baseline. The evaluation is Docker simulation only. |
| "IEEE" fog DT compromised-node detection | Alanezi and Mishra, *IEEE Systems Journal* 18(2), 2024 ([IEEE Xplore](https://ieeexplore.ieee.org/document/10555297/)) | **Accurate, under-specified** | Name the venue. The detector is an MLP trained on malicious-behaviour data. The paper detects compromised nodes; it does not argue for firewalling them. |
| Snort + Eclipse Ditto "on a Raspberry Pi" | El-Hajj, *Electronics* 13(19):3941, 2024 ([DOI](https://doi.org/10.3390/electronics13193941)) | **Mostly accurate** | Ditto ran in Docker on a PC, and the Pi was the IoT device. Floods were caught by Snort, which is signature- and rule-based, not by "rate-based methods." |

The Causio-TwinChain bullet matters most because it sits under the README's architectural claim that "splitting fast detection from slow diagnosis is empirically better than one combined stage." The paper's abstract claims "15.3% higher F1-score in novel attack detection," a diagnosis time "reduced … by 68%" and a false-positive rate "reduced … by 22%," all against benchmark IDS baselines ([PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)). The paper credits the speed-up jointly to "DT synchronization, efficient computations in the latent space, and organized causal tracing." Its only ablations vary latent dimension and threshold percentile. Its Table 1 false-positive rates (2.9% against 6.8%, 4.8% and 5.1%) give relative reductions of about **57%, 40% and 43%**, not 22%. The article also contradicts itself: accuracy is 97.8% in the table and 98.7% in the text, two hardware specifications are given, and the consensus mechanism is described three different ways. The evaluation simulates about 150–200 nodes on N-BaIoT ([PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)). It should not carry any of the argument. Suggested replacement:

> **Two-stage pipelines that separate anomaly flagging from causal diagnosis are an emerging design in digital-twin IoT security.** Dutta et al. (*Scientific Reports* 16:15732, 2026, doi:10.1038/s41598-026-47104-6) chain a contrastive-learning anomaly detector to a structural-causal root-cause stage and a blockchain audit log. In simulation on N-BaIoT, they report a 68% shorter mean time to diagnosis and a 22% lower false-positive rate than benchmark IDS baselines. The paper does not isolate the contribution of the stage split, so we cite it as precedent for the architecture, not as evidence that splitting the stages is better. SentinelTwin's own ablation (security layer before vs. inside diagnosis) tests that question directly.

For the rate-monitoring bullet, the 50× figure is sound. The paper reports "a 50-fold increase in packet rate during DoS," with mean PPS rising from about **13.75 to about 779** ([PubMed](https://pubmed.ncbi.nlm.nih.gov/41471470/)), and the authors present it as a low-cost, interpretable first line of defence while conceding that ML "may achieve higher accuracy in classifying complex attack types." Two phrases are not supported by the verified material. "Exactly what RateTracker implements" is wrong, because Rodrigues uses a μ+3σ threshold on baseline traffic, while RateTracker flags a multiple of the baseline cadence. And the claim that twin traffic is "cyclical and predictable" could not be confirmed as the paper's own wording. Suggested replacement:

> **Lightweight statistical rate monitoring is a defensible first line of defence for digital-twin traffic.** Rodrigues et al. (*Sensors* 25(24):7476, 2025, doi:10.3390/s25247476) flag attacks when packet or byte rates exceed a μ+3σ baseline threshold. In a Docker-simulated testbed, they observed roughly a 50-fold rise in packet rate during DoS. `security.RateTracker` follows the same principle: a learned per-device baseline cadence with an explainable threshold (a multiple of baseline rather than μ+3σ, a choice we compare in our evaluation).

For the fog-twin bullet, the abstract describes a fog-hosted twin that flags nodes that "produce erroneous data or attack other nodes," with an MLP giving the best results ([arXiv 2308.10180](https://arxiv.org/abs/2308.10180)). The abstract puts erroneous data and attacks under one "misbehaving" label. That is a useful foil, because SentinelTwin separates them. Suggested replacement:

> **Digital twins can detect compromised nodes that emit false data or attack neighbours.** Alanezi and Mishra (*IEEE Systems Journal* 18(2), 2024, doi:10.1109/JSYST.2024.3403500) host per-node twins on a fog server and detect misbehaving nodes with an MLP. Their abstract treats erroneous data and attacks as one class. SentinelTwin separates benign faults from attacks so that only attacks trigger firewalling.

For the Snort bullet, El-Hajj ran Ditto in Docker on a PC with an MQTT-linked Raspberry Pi, used Snort as the IDS and Kali as the attacker, and ran Hping3 floods and NMAP scans. Snort produced only **2 alerts for a standard scan and 1 for an aggressive scan**. Memory stayed elevated after scans, which "suggests the need for better recovery mechanisms" ([U. Twente](https://research.utwente.nl/en/publications/leveraging-digital-twins-and-intrusion-detection-systems-for-enha/)). That last observation is a direct motivation for self-healing, and the README should use it. Suggested replacement:

> El-Hajj (*Electronics* 13(19):3941, 2024, doi:10.3390/electronics13193941) paired an Eclipse Ditto twin (Docker, PC) with a Raspberry Pi device and a Snort IDS. Hping3 floods were detected reliably, but NMAP scans raised only one or two alerts. Resource usage stayed elevated after attacks, which the author notes "suggests the need for better recovery mechanisms." SentinelTwin shares the reconnaissance blind spot and addresses the recovery gap.

## Five gaps remain open, and SentinelTwin touches all of them

**First, there is no joint benchmark.** A targeted search for IoT datasets that label sensor faults and cyberattacks together returned only attack-labelled flow datasets ([PMC13068586](https://pmc.ncbi.nlm.nih.gov/articles/PMC13068586/); [CIC](https://www.unb.ca/cic/datasets/tabular-iot-attack-2024.html)). The fault benchmarks contain no adversarial class ([de Bruijn et al.](https://research.utwente.nl/en/publications/benchmark-datasets-for-fault-detection-and-classification-in-sens/)). The nearest neighbour, an EWSN 2023 office IoT concept-drift dataset, includes "anomalous drift" caused by attacks but no labelled hardware faults ([EWSN 2023](https://www.ewsn.org/file-repository/ewsn2023/SPICES%202023-final8390.pdf)). Absence of evidence from one search is not proof of absence. Power-system datasets that label natural events separately from attacks may partly cover the idea, which is why the claim must stay at "to our knowledge."

**Second, drift-shaped tampering is unsolved.** The detection penalty for drift-type false-data injection ([Computers 2026](https://doi.org/10.3390/computers15080534)) and the open replay-versus-bias problem ([Eur. J. Control](https://www.sciencedirect.com/science/article/abs/pii/S0947358021000844)) mean that a model-free rule set will, by construction, label a patient attacker who imitates drift as "sensor drift." Measuring and publishing that confusion honestly is itself a contribution.

**Third, recovery is rarely verified or measured consistently.** MTTR is defined as detection-to-recovery in some papers, as expected repair time in others, and as mean time to *resolution* in network operations ([arXiv 2512.22721](https://arxiv.org/pdf/2512.22721)). One IoMT twin paper splits recovery into Mean Time to Contain and Mean Time to Recover ([arXiv 2606.21513](https://arxiv.org/pdf/2606.21513)). A companion paper by overlapping authors calls its 99.8% recovery success rate an **aspirational target, not a validated result** ([arXiv 2606.21422](https://arxiv.org/pdf/2606.21422)). That shows how weak the reporting norms are.

**Fourth, nobody prices a wrong quarantine.** This search found no response paper that measures the cost of quarantining a device that was only faulty, and no evaluation of MQTT broker-side rate limiting or escalating ban durations. MQTT research is mostly datasets and ML detectors ([PMC12590255](https://pmc.ncbi.nlm.nih.gov/articles/PMC12590255/)).

**Fifth, simple trust models are unevaluated against the attacks they are known to be weak to.** No 2022-2026 paper evaluates EMA trust under on-off or slow-poisoning behaviour, even though static schemes are known to be exploitable ([TJEECS](https://journals.tubitak.gov.tr/elektrik/vol29/iss2/21)).

These gaps line up with SentinelTwin's existing modules, which is why the contributions below need targeted experiments, not new architecture.

## No dataset covers all three classes, so the evaluation must be composite

Almost every major IoT security dataset works at the network-flow or packet level and labels only benign versus attack. Only the TON_IoT telemetry files and the ICS datasets carry sensor values together with attack labels, and none of them labels benign hardware faults.

| Dataset | Level | Labels | Fit for SentinelTwin | Access |
|---|---|---|---|---|
| TON_IoT telemetry (Alsaedi et al., IEEE Access 2020) | Sensor values (weather, thermostat, fridge, GPS, Modbus) | Normal/attack plus attack type | **Best public match** for value-level tampering on temperature/humidity-like streams | IEEE DataPort; download links reported broken ([DataPort](https://ieee-dataport.org/documents/toniot-datasets)) |
| MQTTset (Vaccari et al., Sensors 2020) | MQTT packets, simulated temp/humidity sensors | Benign plus MQTT flood/DoS/brute force | Protocol-faithful DoS replay; used in **65%** of MQTT IDS studies ([IIETA](https://iieta.org/node/21846)) | Public ([PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7698741/)) |
| CICIoMT2024 | Network, Wi-Fi/MQTT/BLE, 40 devices | 18 attacks incl. MQTT class | Second MQTT DoS source; flood-dominated ([UNB CIC](https://unb.ca/cic/datasets/iomt-dataset-2024.html)) | DataPort 10.21227/tq0p-ag21 |
| CICIoT2023 (Neto et al., Sensors 2023) | Flows, 105 devices | 33 attacks / 7 classes | Related work only; no sensor values ([MDPI](https://www.mdpi.com/1424-8220/23/13/5941/html)) | UNB CIC |
| Edge-IIoTset (Ferrag et al., IEEE Access 2022) | Network/protocol, includes temp/humidity devices | 14 attacks | FL extension; academic licence ([DataPort](https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications)) | DataPort / Kaggle |
| MQTT-IoT-IDS2020 (Hindy et al.) | MQTT network | Scans, brute force | Weak: **sensor payloads are random** ([DataPort](https://ieee-dataport.org/open-access/mqtt-internet-things-intrusion-detection-dataset)) | DataPort |
| de Bruijn et al. 2016 (Intel Lab, SensorScope, Smart Santander) | Sensor values, about 5.8M points | Injected random, malfunction, bias, drift, polynomial drift | **Best fault/drift source** for temp/humidity ([SciTePress](https://www.scitepress.org/Papers/2016/56379/56379.pdf)) | Licence and availability not verified |
| HAI (Shin et al., CSET 2020/21) | ICS process telemetry | Attacks | External validity with injected faults; open ([GitHub](https://github.com/icsdataset/hai)) | GitHub/Kaggle |
| SWaT/WADI (iTrust) | ICS telemetry | Attacks | Same as HAI, but request-only and no redistribution ([iTrust](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/terms-of-usage/)) | Request form |
| UCI Gas Sensor Array Drift | 16 MOX sensors, 36 months | Gas class by batch | Real long-term drift, but a classification task; weak transfer to DHT22 ([UCI](https://archive.ics.uci.edu/dataset/224/gas+sensor+array+drift+dataset)) | CC BY 4.0 |

The evaluation design that follows from this has three tiers.

**Tier A is the physical rig, and it is the only place all classes coexist.** Run scripted injections on ESP32/DHT22 nodes with ground-truth timestamps:
- hardware faults: stuck value, dropout, spike;
- network failure: Wi-Fi or broker disconnect;
- drift: a slow additive ramp in firmware;
- tampering: abrupt offset and slow ramp from a rogue publisher;
- MQTT flood;
- identity spoofing.

Use the Attarha and Förster fault-model taxonomy (bias, drift, noise, gain, outliers, stuck) to justify the injection set ([IFIP WONS 2024](https://dl.ifip.org/db/conf/wons/wons2024/1570970228.pdf)).

**Tier B tests detection and diagnosis on real data.** Replay Intel Lab traces with de Bruijn-style injected faults through the MQTT ingest.

**Tier C tests the security layer on someone else's data.** Replay TON_IoT weather and thermostat telemetry for value-level tampering, and MQTTset or CICIoMT2024 floods for DoS. Use HAI with injected faults as an optional external-validity check.

Network-flow datasets (Bot-IoT, N-BaIoT, CICIoT2023) suit a value-level per-device twin poorly. A 2025 critical review notes they routinely produce near-99% accuracy that hides testbed and feature artefacts ([Wiser Pub](https://ojs.wiserpub.com/index.php/CNC/article/view/7228)). Reporting per-class macro-F1 on temporally split data protects against that criticism.

Metrics should be defined with explicit timestamps: onset *t₀*, detection *t_d*, diagnosis *t_g*, recovery start *t_r* and verified restore *t_v*.

| Layer | Metrics |
|---|---|
| Detection | Precision, recall, F1, false alarms per device-hour, MTTD = *t_d − t₀* (median and p95) |
| Diagnosis | 6×6 confusion matrix over {hardware, network, drift, tamper, DoS, spoof}, macro-F1, time-to-diagnose *t_g − t_d*; **drift↔tamper confusion reported separately** |
| Response | Mean time to contain (*t_r − t_d*), MTTR = *t_v − t_d*, verified recovery success rate (verified restores / attempts), false-recovery rate (actions on benign events), **false-quarantine rate and downtime caused** (faults firewalled), availability = uptime/(uptime + downtime) |
| Trust | AUC separating honest from malicious devices, time to cross the quarantine threshold, trust recovery time after a false alarm, behaviour under on-off cycles |
| Overhead | CPU, RAM and end-to-end latency per message, on server and (optionally) ESP32 |

Use the standard three-arm design: fault-free, faults without self-healing, and faults with self-healing ([arXiv 2302.05336](https://arxiv.org/pdf/2302.05336)). For a comparative recovery result to aim at, a simulated Q-learning self-healer cut mean recovery time by **51.9% against random and 32.8% against rule-based** policies ([Gazi Univ. J. Sci.](https://www.citedrive.com/en/discovery/reinforcement-learning-based-self-healing-framework-in-iot-sensor-networks/)). That is a simulation number, and SentinelTwin can beat it on credibility by measuring on hardware.

## Five contributions are defensible, ranked by novelty times feasibility

The ranking below scores each candidate on how clearly the notes show a gap (novelty) and how much a Python plus ESP32 team can finish in one paper cycle (feasibility). Things SentinelTwin should **not** claim as novel are per-device twin anomaly detection, frozen-baseline or rolling z-scores, EMA trust, MAPE-K self-healing, multi-class rule-based RCA as such, and statistical rate-based DoS detection. Each of these appears in the sources above.

| Rank | Contribution | Novelty | Feasibility | What it requires |
|---|---|---|---|---|
| 1 | **Open labelled fault + drift + attack trace from a physical ESP32/DHT22 MQTT testbed, with the injection harness** | High (no joint benchmark found) | High | Two to four weeks of runs, a labelling schema, a release on Zenodo or IEEE DataPort |
| 2 | **Measured separation of drift from slow, drift-shaped tampering**, using a co-located reference sensor (the standby DHT22) plus security-layer co-signals (publisher identity, rate, multi-metric consistency) | High (open problem in the literature) | Medium | One extra sensor per node, ramp-attack scripts, a confusion analysis across ramp slopes |
| 3 | **Formalised post-action closed-loop verification** with phase-level metrics (contain, recover, verify) and an escalation path when verification fails | Medium-high (validation flagged as missing; NMRG covers only pre-action) | High | Already mostly built; needs timestamps and failure-injection during recovery |
| 4 | **Cost of misdiagnosis**: false-quarantine rate and downtime when a fault is labelled as an attack, comparing an escalating, time-boxed, reversible firewall with permanent blocking | Medium-high (no evaluation found) | High | Cross-class injection runs and a downtime accounting script |
| 5 | **Trust robustness**: symmetric against asymmetric EMA under on-off and slow-poisoning devices | Medium | High | A simulation harness plus a short rig run |
| 6 | On-device z-score on the ESP32 against server-side detection (latency and bypass analysis) | Low-medium | High | A firmware port; make it an ablation, not a headline |
| 7 | LLM explainer or planner behind the deterministic guard and verifier | Medium | Medium-low | Future work; frame it with the hallucination literature |
| 8 | Trust-weighted federated aggregation across per-device twins | Medium | Low | Future work only |

Contributions 1 to 4 reinforce each other and should be the paper's core. The single-sentence claim would be: *to our knowledge, the first explainable digital-twin framework evaluated on a physical low-cost IoT testbed that jointly diagnoses benign hardware, network and drift faults and malicious tampering on the same telemetry, verifies its recovery actions after acting, and quantifies the cost of misdiagnosis, with the labelled trace released openly.* Contribution 2 is where the measurable novelty sits. The honest version reports the slope below which ramp tampering becomes indistinguishable from drift, instead of claiming a perfect separation. That is the result reviewers will remember.

### Baselines that make the comparison credible

Each component needs a simple, recognisable comparison. **Detection** should be compared with a rolling-only z-score (showing the frozen baseline's value on slow drift), a fixed-threshold detector, an Isolation Forest or small autoencoder (ESP32-feasible, per the edge results above), and ADWIN or Page-Hinkley from the River library on twin residuals. **Diagnosis** should be compared with a one-stage design that sends everything straight to the diagnoser without the security layer. That one ablation is the experiment the Causio-TwinChain bullet currently borrows evidence for. Add a decision-tree or random-forest classifier trained on the same features, to show the accuracy-versus-explainability trade-off. **DoS detection** should compare the multiple-of-baseline rule with Rodrigues's μ+3σ rule. **Response** should compare no healing, naive restart on any anomaly, and permanent blocking against the time-boxed escalation. **Trust** should compare symmetric EMA, asymmetric EMA and a beta-reputation model. Run every configuration with repeated seeds, and report medians with interquartile ranges.

### What must be checked before any novelty claim

Before submission, the team should check six things:
- Search Google Scholar, IEEE DataPort, Kaggle and Zenodo for IoT datasets labelled with both "fault" and "attack." In particular, check the Mississippi State/ORNL power-system attack datasets, which reportedly label natural events separately from attacks.
- Read the full EWSN/SPICES 2023 paper.
- Read the full 2026 *Scientific Reports* virtual-sensor paper, for its recovery-verification claims.
- Read the full Alanezi and Mishra paper, to confirm it does not separate faults from attacks.
- Search for "post-recovery verification" and "self-healing IoT testbed" in COMST and ACM CSUR resilience surveys from 2023 to 2026.
- Look up ETSI ZSM and ENI closed-loop specifications, which this research did not cover.

If any of these turns up a direct precedent, narrow the claim to the specific combination plus the hardware evaluation.

### Venues that fit a student prototype

IEEE Internet of Things Journal is the stretch target, with a JCR 2024 impact factor of **8.9** and about 6.9 weeks to first decision ([IEEE IoT-J](https://ieee-iotj.org/history/impactfactorsperyear/)). Realistically it needs multi-dataset evaluation and strong learned baselines. The better first step is a prototype-friendly IEEE conference listed in IEEE Xplore: **IEEE WF-IoT**, **COMSNETS** (main track or graduate forum), **IEEE CNSM or NOMS** short or demo tracks (a natural thematic fit for autonomic management), or **IEEE INDICON** for an India-based team. After that, extend to Elsevier *Internet of Things*, *Computer Networks*, IEEE Access or MDPI *Sensors*, and publish the trace separately as a data article in *Data in Brief*. Acceptance rates, APCs and deadlines for these venues were not verified in this research. Confirm every venue on Scopus Sources or the Clarivate Master Journal List, because hijacked clones copy real journal names. Avoid unsolicited calls promising acceptance within one to two weeks.

## Conclusion

SentinelTwin's research value moved from "a self-healing IoT system" to a narrower and stronger claim: a measurement of how well an explainable twin can tell a broken sensor from a lying one, on real hardware, and what happens when it gets that wrong. The literature has many accurate detectors and a few recovery loops. It is missing joint ground truth, honest numbers on the drift-versus-tampering boundary, verified recovery and the cost of false quarantine. Each of these can be measured with the code that already exists, an extra DHT22 and careful timestamping.

The README's current framing works against that strength. It leans on one inconsistent 2026 paper for a causal claim that SentinelTwin can test itself with a single ablation. Replacing borrowed evidence with its own measurements turns the weakest part of the project's write-up into its most original contribution.

## References

### Verified (record checked against a publisher, PMC, arXiv, DBLP, standards body or repository page during this research)

1. A. K. Dutta, M. Anjum, H. Min, Y. I. Daradkeh, J. T. Seo, S. Shahab, "Digital twin-assisted blockchain IoT security model using contrastive and causal learning techniques," *Scientific Reports* 16:15732, 2026. DOI 10.1038/s41598-026-47104-6. https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/
2. Rodrigues et al., "A Data Rate Monitoring Approach for Cyberattack Detection in Digital Twin Communication," *Sensors* 25(24):7476, 2025. DOI 10.3390/s25247476. https://pmc.ncbi.nlm.nih.gov/articles/PMC12736672/ (full author list not confirmed)
3. K. Alanezi, S. Mishra, "An IoT Architecture Leveraging Digital Twins: Compromised Node Detection Scenario," *IEEE Systems Journal* 18(2), 2024. DOI 10.1109/JSYST.2024.3403500. https://ieeexplore.ieee.org/document/10555297/ ; arXiv 2308.10180
4. M. El-Hajj, "Leveraging Digital Twins and Intrusion Detection Systems for Enhanced Security in IoT-Based Smart City Infrastructures," *Electronics* 13(19):3941, 2024. DOI 10.3390/electronics13193941. https://doi.org/10.3390/electronics13193941
5. Q. Xu, S. Ali, T. Yue, "Digital Twin-based Anomaly Detection in Cyber-physical Systems" (ATTAIN), ICST previous-editions track. https://www.simula.no/publications/anomaly-detection-digital-twin-cyber-physical-systems
6. Q. Xu, S. Ali, T. Yue, LATTICE, arXiv 2309.15995, 2023. https://arxiv.org/abs/2309.15995
7. "Hierarchical multi-attention neural networks for sensor fault diagnosis and mitigation in digital twins," *Scientific Reports*, 2026. https://www.nature.com/articles/s41598-026-42046-5 (authors not captured)
8. "Digital Twin-Based Automated Fault Diagnosis in Industrial IoT Applications," *CMC*, about 2023. https://www.sciencedirect.com/org/science/article/pii/S1546221823004769
9. "An Efficient Fault Diagnosis Framework for Digital Twins Using Optimized Machine Learning Models in Smart Industrial Control Systems," *Int. J. Computational Intelligence Systems*, 2023. https://link.springer.com/article/10.1007/s44196-023-00241-6
10. DT fault diagnosis for PV DC–DC converters, 2025. https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12300130/
11. Ground-truth-aware stress testing of a closed-loop smart-building DT, arXiv 2608.14917, 2026. https://arxiv.org/pdf/2608.14917
12. S. Mihai, M. Yaqoob, H. V. Dang et al., "Digital Twins: A Survey on Enabling Technologies, Challenges, Trends and Future Prospects," *IEEE Commun. Surveys & Tutorials* 24(4):2255–2291, 2022. DOI 10.1109/COMST.2022.3208773. https://research.edgehill.ac.uk/en/publications/digital-twins-a-survey-on-enabling-technologies-challenges-trends/
13. A. Zhang et al. (Microsoft / Nanjing Univ.), "The Vision of Autonomic Computing: Can LLMs Make It a Reality?" arXiv 2407.14402, 2024. https://arxiv.org/abs/2407.14402
14. "A Survey on Resilience in the IoT: Taxonomy, Classification and Discussion of Resilience Mechanisms," arXiv 2109.02328, 2021. https://arxiv.org/pdf/2109.02328
15. Hong, "A Comprehensive Survey on LLM-Based Network Management and Operations," *Int. J. Network Management*, 2025. DOI 10.1002/nem.70029. https://onlinelibrary.wiley.com/doi/full/10.1002/nem.70029 (quoted from a snippet; full author list not captured)
16. C. Zhou et al., "Network Digital Twin: Concepts and Reference Architecture," draft-irtf-nmrg-network-digital-twin-arch-13, IRTF NMRG, July 2026 (Informational draft). https://datatracker.ietf.org/doc/draft-irtf-nmrg-network-digital-twin-arch/
17. ITU-T Y.3090, "Digital twin network – Requirements and architecture," Feb 2022. https://www.itu.int/rec/T-REC-Y.3090-202202-I/en
18. P. Almasan et al., "Network Digital Twin: Context, Enabling Technologies, and Opportunities," *IEEE Communications Magazine* 60(11):22–27, 2022. DOI 10.1109/MCOM.001.2200012. https://arxiv.org/abs/2205.14206
19. F. Delaine, B. Lebental, H. Rivano, "In Situ Calibration Algorithms for Environmental Sensor Networks: A Review," *IEEE Sensors Journal* 19(15), 2019. DOI 10.1109/JSEN.2019.2910317. https://hal.archives-ouvertes.fr/hal-02174938
20. F. Delaine et al., "Framework for the Simulation of Sensor Networks Aimed at Evaluating In Situ Calibration Algorithms," *Sensors* 20(16), 2020. https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7472635/
21. Concas et al., "Low-Cost Outdoor Air Quality Monitoring and Sensor Calibration: A Survey and Critical Analysis," *ACM Trans. Sensor Networks*, 2021. DOI 10.1145/3446005. https://dl.acm.org/doi/fullHtml/10.1145/3446005
22. Waqas et al., "Enhancing IoT Sensors Precision Through Sensor Drift Calibration With Variational Autoencoder," 2024 (accepted manuscript). https://gala.gre.ac.uk/id/eprint/49196/ (venue not captured)
23. DT-based virtual sensors for smart swine barns, *Sensors* 25(24):7690, 2025. https://www.mdpi.com/1424-8220/25/24/7690
24. L. Pham et al., "RCAEval: A Benchmark for Root Cause Analysis of Microservice Systems," WWW '25 Companion; arXiv 2412.17015. https://arxiv.org/abs/2412.17015
25. ST-GraphRCA, spatio-temporal graph-propagation RCA for IoT edge computing. https://pmc.ncbi.nlm.nih.gov/articles/PMC12987278/
26. Y. Chen et al., "Automatic Root Cause Analysis via Large Language Models for Cloud Incidents" (RCACopilot), arXiv 2305.15778. https://arxiv.org/abs/2305.15778
27. D. Wu et al., "NetLLM: Adapting Large Language Models for Networking," ACM SIGCOMM 2024; arXiv 2402.02338. https://arxiv.org/abs/2402.02338
28. C. Wang, M. Scazzariello, A. Farshin, S. Ferlin, D. Kostić, M. Chiesa, "NetConfEval: Can LLMs Facilitate Network Configuration?" *Proc. ACM Netw.* (CoNEXT 2024). DOI 10.1145/3656296.
29. "Autonomous Incident Resolution at Hyperscale: An Agentic AI Architecture for Network Operations," arXiv 2606.09122, 2026. https://arxiv.org/pdf/2606.09122
30. Kramer et al., LLMs in security incident response, USENIX SOUPS 2025. https://www.usenix.org/system/files/soups2025-kramer.pdf
31. T. Roy, S. Dey, distinguishing physical faults from actuation cyberattacks, arXiv 2311.09342, 2023. https://arxiv.org/abs/2311.09342
32. Dual UIO plus Luenberger observer for faults and cyber attacks in interconnected CPS, *Control Engineering Practice*, 2024. https://www.sciencedirect.com/science/article/abs/pii/S0967066124003757 (snippet; authors not captured)
33. Replay attack versus sensor bias in event-triggered CPS, *European Journal of Control*, 2021. https://www.sciencedirect.com/science/article/abs/pii/S0947358021000844 (snippet)
34. Drift-type versus spike FDI in smart meters, *Computers* 15(8):534, 2026. DOI 10.3390/computers15080534 (snippet; authors not captured)
35. "Digital Twin-Driven Intrusion Detection for Industrial SCADA: A Cyber-Physical Case Study," *Sensors* 25(16):4963, 2025. https://www.mdpi.com/1424-8220/25/16/4963
36. "Digital Twin-Enabled Incident Detection and Response: A Systematic Review of Critical Infrastructures Applications," *Int. J. Information Security*, 2025. DOI 10.1007/s10207-025-01113-0 (snippet; authors not captured)
37. "Enhancing IIoT Security Using Digital Twins in Industry 5.0: A Systematic Literature Review," *Information* 17(2):209. DOI 10.3390/info17020209 (snippet)
38. D. Konsta, A. Lluch Lafuente, N. Dragoni, "Trust Management for Internet of Things: A Systematic Literature Review," arXiv 2211.01712. https://arxiv.org/abs/2211.01712
39. "IoT trust and reputation: a survey and taxonomy," arXiv 2304.06119. https://arxiv.org/abs/2304.06119
40. "Beyond Detection Accuracy: Measuring Explanation Cost, Stability, and Utility for Resource-Aware IoT Intrusion Detection," arXiv 2608.10349, 2026. https://arxiv.org/pdf/2608.10349
41. "Evaluation of Explainable AI in IoT IDS Under DeepFool Adversarial Conditions," *Sensors* 26(10):2924, 2026. DOI 10.3390/s26102924 (snippet)
42. A. Alsaedi, N. Moustafa, Z. Tari, A. Mahmood, A. Anwar, "TON_IoT Telemetry Dataset," *IEEE Access* 8:165130–165150, 2020. DOI 10.1109/ACCESS.2020.3022862. https://doaj.org/article/478764ecbd9b4168a278f4c7154ce88c
43. E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, A. A. Ghorbani, "CICIoT2023," *Sensors* 23(13):5941, 2023. DOI 10.3390/s23135941. https://www.mdpi.com/1424-8220/23/13/5941/html
44. S. Dadkhah et al., "CICIoMT2024: Attack Vectors in Healthcare devices," *Internet of Things* 28, 2024. https://unb.ca/cic/datasets/iomt-dataset-2024.html (data DOI 10.21227/tq0p-ag21; article DOI not retrieved)
45. M. A. Ferrag et al., "Edge-IIoTset," *IEEE Access* 10:40281–40306, 2022. DOI 10.1109/ACCESS.2022.3165809. https://doaj.org/article/72942bebe6e845e3a0fbefd31f12be06
46. H. Hindy et al., "Machine Learning Based IoT Intrusion Detection System: An MQTT Case Study (MQTT-IoT-IDS2020 Dataset)," INC 2020; arXiv 2006.15340. https://strathprints.strath.ac.uk/75251/
47. I. Vaccari et al., "MQTTset, a New Dataset for Machine Learning Techniques on MQTT," *Sensors* 20(22):6578, 2020. https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7698741/
48. T. de Bruijn et al., "Benchmark Datasets for Fault Detection and Classification in Sensor Data," SENSORNETS 2016. https://www.scitepress.org/Papers/2016/56379/56379.pdf
49. H.-K. Shin et al., "HAI 1.0: HIL-based Augmented ICS Security Dataset," USENIX CSET 2020. https://www.usenix.org/conference/cset20/presentation/shin
50. UCI Gas Sensor Array Drift Dataset (CC BY 4.0). https://archive.ics.uci.edu/dataset/224/gas+sensor+array+drift+dataset
51. Attarha and Förster, sensor fault model review, IFIP WONS 2024. https://dl.ifip.org/db/conf/wons/wons2024/1570970228.pdf
52. ArrythML, ESP32-S3 autoencoder, arXiv 2606.02256, 2026. https://arxiv.org/html/2606.02256v1
53. Unsupervised TinyML Isolation Forest on ESP32 for industrial environments, *Sensors*. https://pmc.ncbi.nlm.nih.gov/articles/PMC9962960/
54. z-score TinyML detector on STM32, arXiv 2604.08581. https://arxiv.org/pdf/2604.08581
55. Campos et al., "Evaluating Federated Learning for Intrusion Detection in Internet of Things: Review and Challenges," arXiv 2108.00974. https://ar5iv.labs.arxiv.org/html/2108.00974
56. Fault-injection three-arm self-healing evaluation, arXiv 2302.05336. https://arxiv.org/pdf/2302.05336
57. Reinforcement-learning self-healing in IoT sensor networks, *Gazi Univ. J. Sci. Part A*. DOI 10.54287/gujsa.1914900
58. IEEE Internet of Things Journal impact-factor history. https://ieee-iotj.org/history/impactfactorsperyear/

### Unverified (from the researchers' prior knowledge or snippets only; check on DBLP or Crossref before citing)

1. J. O. Kephart, D. M. Chess, "The Vision of Autonomic Computing," *IEEE Computer* 36(1):41–50, 2003. DOI 10.1109/MC.2003.1160055.
2. O. Gheibi, D. Weyns, F. Quin, "Applying Machine Learning in Self-Adaptive Systems: A Systematic Literature Review," ACM TAAS, 2021.
3. J. Lu et al., "Learning under Concept Drift: A Review," IEEE TKDE 31(12), 2019. DOI 10.1109/TKDE.2018.2876857.
4. T. Ahmed et al., "Recommending Root-Cause and Mitigation Steps for Cloud Incidents using Large Language Models," ICSE 2023 (arXiv 2301.03797 unconfirmed).
5. L. Pham, H. Ha, H. Zhang, "Root Cause Analysis for Microservice System based on Causal Inference: How Far Are We?" ASE 2024 (artifact: https://zenodo.org/records/13305663).
6. D. Wang et al., REASON, KDD 2023 (arXiv 2302.01987; venue unconfirmed).
7. RCACopilot's venue as EuroSys 2024.
8. Y. Meidan et al., "N-BaIoT," *IEEE Pervasive Computing* 17(3):12–22, 2018 (DOI not retrieved).
9. N. Koroniotis et al., Bot-IoT, *Future Generation Computer Systems* 100, 2019. DOI 10.1016/j.future.2019.05.041.
10. A. Vergara et al., "Chemical gas sensor drift compensation using classifier ensembles," *Sensors and Actuators B*, 2012. DOI 10.1016/j.snb.2012.01.074.
11. Goh et al. (SWaT, CRITIS 2016); Ahmed et al. (WADI, CySWATER 2017).
12. Belenguer et al., FL review for IoT IDS (arXiv 2204.12443; venue unconfirmed).
13. Nguyen et al., "DÏoT," IEEE ICDCS 2019; Rey et al., FL for IoT malware detection, *Computer Networks* 2022.
14. L. Yang, D. M. Manias, A. Shami, "PWPAE," IEEE GLOBECOM 2021.
15. A. Bifet, R. Gavaldà, ADWIN, SIAM SDM 2007; E. S. Page, "Continuous Inspection Schemes," *Biometrika* 1954; J. Montiel et al., "River," JMLR 22(110), 2021; J. Gama et al., ACM CSUR 46(4), 2014.
16. Y. Wu, K. Zhang, Y. Zhang, "Digital Twin Networks: A Survey," IEEE IoT Journal 8(18), 2021. DOI 10.1109/JIOT.2021.3079510 (one index only).
17. Ge et al., "Proactive Defense for Internet-of-Things: Moving Target Defense with Cyberdeception," ACM TOIT 2022 (co-authors unconfirmed).
18. Oikonomou et al., SPICES@EWSN 2023 office IoT concept-drift dataset (exact title and authors unconfirmed).
19. Mississippi State / ORNL power-system attack datasets labelling natural events separately from attacks (relevant to the "no joint dataset" claim).
20. "Gyawali et al." on turning SHAP, LIME and counterfactual explanations into mitigations (paper not identified).
21. "Self-Running Networks: A Comprehensive Survey" (ResearchGate 393933089; authors and venue unresolved; treat as a preprint).
22. Venue facts not verified this session: IEEE Access and MDPI APCs and acceptance rates; acceptance rates for WF-IoT, COMSNETS, INDICON, NOMS and CNSM; MDPI status in national rating lists.
