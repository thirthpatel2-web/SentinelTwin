# Digital-Twin IoT Security, Fault-vs-Attack Disambiguation, Trust Management, and Explainable IDS (2022-2026)

Scope note: the notes come from about 18 search and fetch calls. Items marked **[snippet-only]** were confirmed only from search-result excerpts, not from the full text. Items marked **[UNVERIFIED]** could not be confirmed. Every other bibliographic record was checked against a publisher, PMC, arXiv, or repository page.

## Q1. Verification of the four README citations

### Takeaway
All four papers exist. Two README claims need correcting:
- **(a) Causio-TwinChain.** The 68% and 22% figures are in the abstract. The paper does not credit them to separating "fast anomaly flagging" from "causal root-cause". It has no ablation that isolates the stages, and the 22% cannot be reproduced from its own Table 1.
- **(c)** The README calls it an "IEEE paper". It is in *IEEE Systems Journal*, so the README should name the venue.

Claims (b) and (d) are accurate.

### Cited Findings

**(a) "Causio-TwinChain": verified to exist, but the README's causal attribution is overstated**
- Record: Ashit Kumar Dutta, Mohd Anjum, Hong Min (corresponding), Yousef Ibrahim Daradkeh, Jung Taek Seo, Sana Shahab. "Digital twin-assisted blockchain IoT security model using contrastive and causal learning techniques." *Scientific Reports* 16:15732 (published 18 Apr 2026). DOI 10.1038/s41598-026-47104-6. PMID 42000899, PMCID PMC13190845. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/); [Nature](https://www.nature.com/articles/s41598-026-47104-6)
- Architecture: digital twin plus contrastive-learning anomaly detection, then structural causal learning for root-cause diagnosis, then a permissioned blockchain for audit logging. The name "Causio-TwinChain" is used for the model in its comparison table. — [Nature](https://www.nature.com/articles/s41598-026-47104-6) [snippet-only for the name]
- Abstract claims, compared against benchmark IDS baselines:
  - "15.3% higher F1-score in novel attack detection"
  - "reduced the mean time for incident diagnosis by 68%"
  - "reduced the false-positive rate by 22%"
  - — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)
- None of the 15.3%, 68% or 22% figures appears in the visible Results text. The 22% does not follow from Table 1's FPRs: the proposed model's 2.9% against the baselines' 6.8%, 4.8% and 5.1% gives relative reductions of about 57%, 40% and 43%. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)
- **Attribution.** The pipeline is sequential: "The framework initiates causal analysis upon anomaly notification in the contrastive learning module."
  - The paper credits the diagnosis speed-up jointly to "DT synchronization, efficient computations in the latent space, and organized causal tracing".
  - There is no per-stage timing and no ablation of the stage split. The only ablations are latent dimension and threshold percentile.
  - The README's wording ("from separating fast anomaly flagging from causal root-cause stage") is therefore an interpretation, not a claim the paper makes.
  - — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)
- **Internal inconsistencies to note if citing:**
  - Accuracy is 97.8% in Table 1 but "98.7%" in the Results text.
  - Two different hardware specs are given (i7/RTX 3060 and i9/RTX 3090).
  - The consensus mechanism is described three ways: PoA, PBFT, and Hyperledger Fabric.
  - Batch size and epochs conflict (512/200 vs 64/100).
  - — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)
- **Testbed.** The evaluation is simulation only. It models "approximately 150–200 heterogeneous IoT nodes" with SciPy state-space twins and uses the N-BaIoT dataset (Mirai/Bashlite traffic, 115 features). There is no physical deployment. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13190845/)
- Caveat: the fetched text was cut off at Table 8, so I did not see the Discussion, Limitations or References.

**(b) 2025 data-rate monitoring study: verified, and the claim is accurate**
- Record: Rodrigues et al. "A Data Rate Monitoring Approach for Cyberattack Detection in Digital Twin Communication." *Sensors* 25(24):7476, published 9 Dec 2025. DOI 10.3390/s25247476, PMID 41471470, PMC12736672. Preprint: Preprints.org 202510.1127 (v2). — [DOI](https://doi.org/10.3390/s25247476); [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12736672/); [Preprint](https://www.preprints.org/manuscript/202510.1127)
  - [UNVERIFIED]: the full author list and first names. Only "Rodrigues et al." was confirmed.
- **Method.** A non-intrusive sniffer measures packets per second (PPS) and bytes per second (BPS). It raises an alert to the DT when traffic exceeds a μ+3σ threshold set from a normal-operation baseline. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12736672/) [snippet-only]
- **Results.** The test was a Docker simulation of DoS, MiTM and intrusion attacks.
  - Each attack type produced a distinct statistical signature, "e.g., a 50-fold increase in packet rate during DoS".
  - Mean PPS was about 13.75 under normal operation and about 779 under DoS (Table 2).
  - — [PubMed](https://pubmed.ncbi.nlm.nih.gov/41471470/) [snippet-only for Table 2]
- **Stated limitation.** The authors concede that state-of-the-art ML/DL "may achieve higher accuracy in classifying complex attack types". They position their method as a low-cost, interpretable first line of defense. Evaluation is Docker simulation only, not hardware. — [PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC12736672/) [snippet-only]

**(c) Fog-based DT for compromised node detection: verified as *IEEE Systems Journal***
- Record: Khaled Alanezi and Shivakant Mishra. "An IoT Architecture Leveraging Digital Twins: Compromised Node Detection Scenario." *IEEE Systems Journal* 18(2), June 2024. DOI 10.1109/JSYST.2024.3403500. Preprint: arXiv:2308.10180 (Aug 2023). — [IEEE Xplore](https://ieeexplore.ieee.org/document/10555297/); [OpenAlex](https://api.openalex.org/works/doi:10.1109/JSYST.2024.3403500); [NSF PAR](https://par.nsf.gov/servlets/purl/10553559); [arXiv](https://arxiv.org/abs/2308.10180)
- **Claim.** A digital twin on a fog server monitors only the information it needs, to save energy and storage. It flags nodes that produce erroneous data or attack other nodes. The prototype was trained on malicious-behavior datasets, with "good accuracy and low overhead", and an MLP gave the best results. — [arXiv](https://arxiv.org/abs/2308.10180)
- Gap for SentinelTwin: the abstract treats "erroneous data" and attacks under one "misbehaving node" label. Nothing in the abstract says it separates benign faults from attacks. This is inferred from the abstract only.

**(d) DT + IDS with Snort, Eclipse Ditto and Raspberry Pi: verified**
- Record: Mohammed El-Hajj (sole author). "Leveraging Digital Twins and Intrusion Detection Systems for Enhanced Security in IoT-Based Smart City Infrastructures." *Electronics* 13(19):3941, Oct 2024. DOI 10.3390/electronics13193941. Preprint: Preprints 202409.0792 ("Digital Twins and Intrusion Detection Systems: A Synergistic Approach to Securing Smart Cities"). — [U. Twente](https://research.utwente.nl/en/publications/leveraging-digital-twins-and-intrusion-detection-systems-for-enha/); [DOI](https://doi.org/10.3390/electronics13193941); [Preprint](https://www.preprints.org/manuscript/202409.0792)
- **Setup:**
  - The twin runs on Eclipse Ditto in Docker on a PC.
  - MQTT links the Raspberry Pi to the twin.
  - Snort is the IDS, and a Kali VM is the attacker.
  - Attacks: Hping3 ICMP/TCP/HTTP floods (including SYN and ACK) and NMAP scans, each run for 5 minutes.
  - — [Preprint](https://www.preprints.org/manuscript/202409.0792); [U. Twente](https://research.utwente.nl/en/publications/leveraging-digital-twins-and-intrusion-detection-systems-for-enha/)
- **Findings:**
  - Snort detected the floods effectively but did poorly on NMAP: 2 alerts for a standard scan and 1 for an aggressive scan.
  - SYN/ACK floods drove CPU usage high.
  - Memory stayed elevated after the NMAP scans, which "suggests the need for better recovery mechanisms". This is a direct motivation for self-healing.
  - Stealthy-scan detection is left as future work.
  - — [U. Twente](https://research.utwente.nl/en/publications/leveraging-digital-twins-and-intrusion-detection-systems-for-enha/); [DOI](https://doi.org/10.3390/electronics13193941) [counts snippet-only]

### Inferences
- The README should cite (a) as "Dutta et al., Sci. Rep. 2026". It should report the 68% and 22% as the authors' abstract-level claims against IDS baselines, with no attribution to the stage split. The article's own inconsistencies mean it should not be a load-bearing citation.
- (b) directly backs SentinelTwin's MQTT message-rate DoS check, which uses simple statistical thresholding.
- (d) is a useful foil. It uses a signature IDS next to a DT, with no diagnosis or fault/attack separation and no automated response, and it documents that recovery is lacking.

### Gaps
- The full Discussion, Limitations and Reference list of (a) were not read.
- Full author names for (b) were not confirmed.

## Q2. Distinguishing benign faults and sensor degradation from attacks

### Takeaway
Fault/attack disambiguation is studied mostly in control theory (observers and residuals) and in power systems (ML on PMU data). It is rarely done in IoT/DT platforms. Two problems remain open:
- stealthy attacks that stay under residual thresholds or mimic drift or bias;
- replay attacks that look like sensor bias.

### Cited Findings
- Roy and Dey propose a sliding-mode unknown-input-observer framework with a "Distinguishability metric" to tell physical faults from actuation cyberattacks. Their argument: "strategies to counteract faults and cyberattacks would be widely different" and it is "vital to not only detect but also to identify the nature of the anomaly." It is simulation only. — Tanushree Roy, Satadru Dey, arXiv:2311.09342 (Nov 2023; submitted to ASME), [arXiv](https://arxiv.org/abs/2311.09342)
- A 2024 *Control Engineering Practice* paper (Elsevier, pii S0967066124003757) combines a dual unknown-input observer with a Luenberger observer and residual-based metrics. It aims to separate "interleaved-action faults and cyber attacks" in interconnected CPS. — [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0967066124003757) [snippet-only; authors not captured]
- Telling replay attacks apart from sensor bias faults in event-triggered CPS is described as "an open problem". The same paper notes that standard fault detection and isolation (FDI) methods "do not consider the stealthiness issue by design". — *European Journal of Control* 2021 (pii S0947358021000844), [ScienceDirect](https://www.sciencedirect.com/science/article/abs/pii/S0947358021000844) [snippet-only; pre-2022 background]
- An ML classifier separates stealthy FDIA on the state estimator from faults in power systems. — "Distinguishing Between Cyber Injection and Faults Using Machine Learning Algorithms", IEEE, [IEEE Xplore 8691899](https://ieeexplore.ieee.org/document/8691899) [snippet-only; about 2018, pre-window]
- Drift-mimicking FDI is the hardest class to detect. In a smart-meter study, detection was 91.4% for drift-type attacks against 98.3% for spikes, because the attacks accumulate small deviations that stay under bad-data thresholds. — *Computers* (MDPI) 15(8):534, 2026, [DOI 10.3390/computers15080534](https://doi.org/10.3390/computers15080534) [snippet-only; authors not captured]
- IoMT FDI is modeled as "smooth gradual or abrupt coordinated modifications" that stay within plausible physiological ranges. The detector uses a Graph-GRU digital twin with Kalman-innovation features, including sensor-correlation drift, and reports F1 94.3% on WUSTL-EHMS-2020. — *Bioengineering* 13(8):920, 2026, [DOI 10.3390/bioengineering13080920](https://doi.org/10.3390/bioengineering13080920) [snippet-only]
- Residual-based limit: an attacker who knows the model can stay within detection thresholds. Such an attacker may still leave non-random traces, which a cumulative-sign detector can catch. — Bonczek and Bezzo, arXiv:2005.07821, [arXiv](https://arxiv.org/pdf/2005.07821) [pre-window]
- A DT-driven SCADA IDS case study reports that "minor drifts in sensor calibration introduced discrepancies between the physical sensor values and the digital twin outputs". In other words, benign drift is itself a source of false positives for DT-residual detectors. — "Digital Twin-Driven Intrusion Detection for Industrial SCADA: A Cyber-Physical Case Study", *Sensors* 25(16):4963, 2025, [MDPI](https://www.mdpi.com/1424-8220/25/16/4963)

### Inferences
- Most rigorous disambiguation needs a physics or state-space model: UIOs, Kalman innovations, distinguishability metrics. SentinelTwin's rule-based diagnosis uses multi-metric signatures (network vs hardware vs sensor drift vs tampering). That approach is lighter and model-free, but it cannot by construction defend against an adversary who imitates drift.
- SentinelTwin should state honestly that slow, drift-shaped FDI is likely to be classified as "sensor drift". The literature supports this as an open problem.

### Gaps
- I found no IoT/DT platform paper that does explicit three-way benign-fault vs attack classification with an evaluation on hardware.
- I did not find a 2022-2026 survey devoted to fault-vs-attack disambiguation.

## Q3. Digital-twin-based intrusion detection for IoT/IIoT/CPS

### Takeaway
DT-IDS work is plentiful. Most of it is evaluated in simulation or on public datasets (N-BaIoT, Docker, simulated plants). Reviews repeatedly name model fidelity, DT–physical synchronization, and scalability as the main limitations. Few systems tie detection to diagnosis and automated recovery.

### Cited Findings
- **Springer systematic review (2025).** "Digital Twin-Enabled Incident Detection and Response: A Systematic Review of Critical Infrastructures Applications", *International Journal of Information Security*, DOI 10.1007/s10207-025-01113-0.
  - It lists as common limitations the difficulty of high-fidelity modeling of dynamic IoT/ICS, real-time synchronization between digital and physical components, and scalability and interoperability.
  - — [Springer](https://link.springer.com/article/10.1007/s10207-025-01113-0) [snippet-only; authors not captured]
- **Industry 5.0 systematic review.** "Enhancing IIoT Security Using Digital Twins in Industry 5.0: A Systematic Literature Review", *Information* 17(2):209, DOI 10.3390/info17020209.
  - It covers 110 studies and names complexity, model fidelity, real-time data processing and scalability as critical gaps.
  - It warns that "low fidelity risks flawed security decisions" and cites a DT-IDS hampered by poor integration of physical data.
  - — [DOI](https://doi.org/10.3390/info17020209) [snippet-only]
- **DT-driven SCADA IDS (*Sensors* 2025, 25(16):4963).**
  - Reports F1 96.3%, FPR below 2.5%, and latency under 500 ms on a *simulated* water-treatment plant.
  - Notes that 100 Hz synchronization caused I/O delays and bottlenecks in the Python–OPC UA interface.
  - — [PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12390215/)
- **Blockchain-enabled secure DT for early botnet detection in IIoT** (PMC9412983, about 2022). — [PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC9412983/) [snippet-only]
- **Virtual cybersecurity department for securing water-distribution digital twins.** CPU and memory usage rose during DoS and helped detect it. — arXiv:2504.20266 (2025), [arXiv](https://arxiv.org/pdf/2504.20266) [snippet-only]
- **DT-empowered smart attack detection for 6G Edge-of-Things.** — arXiv:2310.03554, [arXiv](https://arxiv.org/pdf/2310.03554) [snippet-only]
- **Q1 papers in this category:**
  - Dutta et al. 2026 (simulation, N-BaIoT)
  - Rodrigues et al. 2025 (Docker)
  - Alanezi and Mishra 2024 (fog DT, MLP)
  - El-Hajj 2024 (Snort + Ditto on Raspberry Pi)
  - — see Q1 for links.

### Inferences
- A recurring pattern across these works is that the DT serves as a monitoring mirror or a data source for an ML classifier. It is not used as a per-device baseline that sits ahead of an explicit fault-vs-attack diagnosis and a time-boxed response. That is SentinelTwin's niche.
- The synchronization and fidelity concerns apply to SentinelTwin too. Per-device twins with simple models trade fidelity for low cost.

### Gaps
- Author lists for the Springer 2025 and *Information* 2026 reviews were not captured.
- I found no comparative benchmark of DT-IDS testbeds.

## Q4. IoT trust management (EMA, Bayesian/beta, subjective logic) and attacks on trust

### Takeaway
Trust models are well surveyed, and trust attacks are well defined: on-off, bad-mouthing, ballot-stuffing, opportunistic service, whitewashing. Static reward/penalty schemes, which simple EMA effectively is, are known to be open to on-off behavior. I found little 2022-2026 work that evaluates plain EMA trust specifically.

### Cited Findings
- **Konsta, Lluch Lafuente and Dragoni**, "Trust Management for Internet of Things: A Systematic Literature Review", arXiv:2211.01712 (v1 Nov 2022, v3 Sep 2023; "submitted to IEEE").
  - It classifies IoT trust-management methods.
  - It defines bad-mouthing, ballot-stuffing, on-off and opportunistic-service attacks as trust-related attacks.
  - — [arXiv](https://arxiv.org/abs/2211.01712); [PDF](https://arxiv.org/pdf/2211.01712) [attack definitions snippet-only]
- **"Trust Attacks and Defense in the Social Internet of Things: Taxonomy and Simulation-Based Evaluation"** (PMC12737177, about 2025).
  - It covers seven attack types, including bad-mouthing, ballot-stuffing and on-off.
  - It summarizes the 2015–2024 surveys and compares defenses in simulation.
  - — [PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12737177/) [snippet-only]
- **Static reward and punishment** lets misbehaving nodes exploit on-off behavior. A dynamic scheme punishes not-serving more heavily than it rewards serving. — *Turkish Journal of Electrical Engineering & Computer Sciences* 29(2), 2021, [TUBITAK](https://journals.tubitak.gov.tr/elektrik/vol29/iss2/21) [pre-window]
- **Recommendation-filtering trust model** (subspace clustering) against bad-mouthing and ballot-stuffing. It claims about 44% better accuracy at detecting on-off attackers. — arXiv:2508.17304 (2025 preprint), [arXiv](https://arxiv.org/html/2508.17304v2)
- **Dynamic trust-related attack detection with a deep LSTM** for IoT devices and services, targeting on-off attacks. — [PMC10144673](https://pmc.ncbi.nlm.nih.gov/articles/PMC10144673/) [snippet-only; about 2023]
- **IDS-based trust survey.** Some Bayesian estimation approaches are computationally heavy and "can be wrong in some cases". — "A Survey of Intrusion Detection-Based Trust Management Approaches in IoT Networks", [ResearchGate](https://www.researchgate.net/publication/369241134_A_Survey_of_Intrusion_Detection-Based_Trust_Management_Approaches_in_IoT_Networks) [snippet-only; venue not verified]
- **Foundational attack analysis.** Sun et al., "Attacks on Trust Evaluation in Distributed Networks", CISS 2006, uses a beta-function trust model. — [UMD PDF](http://sig.umd.edu/publications/Sun_CISS_200603.pdf) [pre-window background]

### Inferences
- SentinelTwin's EMA trust is a single-observer, direct-evidence model with no recommendations. That makes it immune to bad-mouthing and ballot-stuffing by design.
- It remains open to:
  - on-off attacks, because EMA forgets bad behavior at a fixed rate;
  - slow poisoning, where small deviations each update trust only slightly.
- Asymmetric decay (faster to lose trust than to regain it) is the standard mitigation in the literature cited above.

### Gaps
- I found no 2022-2026 paper that evaluates EMA-based IoT trust under on-off or slow-poisoning attacks.
- I did not find a subjective-logic IoT paper in this pass.
- [UNVERIFIED] "Slow poisoning" as a named trust attack: no source captured.

## Q5. Explainable AI for IoT IDS and anomaly detection

### Takeaway
XAI-IDS work is dominated by post-hoc SHAP and LIME on ML classifiers. The critiques fall into three groups:
- **Cost.** SHAP is expensive on large feature spaces.
- **Instability.** LIME is unstable under perturbation.
- **Low fidelity.** High accuracy does not imply a faithful explanation.

Explanations show associations, not causes, and are rarely tied to a response. Only isolated works turn explanations into mitigations.

### Cited Findings
- **"Explainable intrusion detection for the internet of things: a systematic literature review"**, *Internet of Things* (Elsevier, pii S2542660526002374, 2026). — [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2542660526002374) [snippet-only; authors not captured]
- **Cost.** SHAP and LIME are computationally heavy and may hinder real-time detection on high-speed networks. SHAP is more stable than LIME but "much more costly to compute, especially when the feature space is large". — search excerpts from the XAI IoT IDS literature, including [Frontiers in AI 2025, 10.3389/frai.2025.1526221](https://www.frontiersin.org/journals/artificial-intelligence/articles/10.3389/frai.2025.1526221/full) [snippet-only; which statement comes from which paper is not confirmed]
- **Adversarial fidelity.** Under DeepFool attacks, high model accuracy does not guarantee high-fidelity explanations. LIME was unstable, while SHAP was more consistent. — "Evaluation of Explainable Artificial Intelligence in IoT Intrusion Detection Systems Under DeepFool Adversarial Conditions", *Sensors* 26(10):2924, 2026, [DOI](https://doi.org/10.3390/s26102924) [snippet-only]
- **Association, not causation.** Post-hoc attributions describe associations inside a fitted model and "do not by themselves establish causal relevance, semantic correctness, or analyst trust". Studies often use one model on one dataset. — "Beyond Detection Accuracy: Measuring Explanation Cost, Stability, and Utility for Resource-Aware IoT Intrusion Detection", arXiv:2608.10349 (2026), [arXiv](https://arxiv.org/pdf/2608.10349) [snippet-only]
- **Logic vs statistics.** A comparison of statistical and logic-based feature attribution for 5G IDS. — arXiv:2509.10206, [arXiv](https://arxiv.org/pdf/2509.10206) [snippet-only]
- **Turning explanations into action.** Gyawali et al. combined SHAP, LIME and counterfactuals to translate predictions into mitigation strategies. It was the only example of this found. — cited in search excerpts [UNVERIFIED: exact paper not identified]
- **Further examples:**
  - "Enhancing AI transparency in IoT intrusion detection using explainable AI techniques", *Internet of Things* (pii S2542660525002288, 2025), [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2542660525002288) [snippet-only]
  - XAI-SOH-FL, federated XAI-IDS, arXiv:2606.00134. It notes that SHAP in federated learning adds communication overhead. — [arXiv](https://arxiv.org/pdf/2606.00134) [snippet-only]

### Inferences
- SentinelTwin's rule-based diagnosis is explainable by design, not post hoc. Each verdict names the rule and metrics that fired, and the verdict selects the response directly: firewall for attacks, healing for faults.
- This answers the "explanations aren't tied to response" critique. The trade-off is weaker generalization to novel attacks than ML.

### Gaps
- Author lists for the Elsevier XAI SLR and the *Sensors* DeepFool paper were not captured.
- The Gyawali et al. citation is unverified.

## Q6. Automated response, moving target defense and quarantine; MQTT-specific attacks and defenses

### Takeaway
Automated IoT response research centers on SDN-based MTD and cyberdeception, plus some quarantine and slicing work. MQTT research is mostly datasets and ML detectors. I found little on broker-side mitigations such as rate limiting or escalating time-boxed blocks.

### Cited Findings
- **MTD in SDN.** A systematic literature review of 2015–2025 SDN MTD work (97 of 302 records, PRISMA) finds most work targets DoS/DDoS and reconnaissance. Stealthy link-flooding, malware propagation and multi-stage threats get little attention. — "Moving Target Defense Meets Artificial Intelligence-Driven Network: A Comprehensive Survey" or a related SLR, [ResearchGate](https://www.researchgate.net/publication/388334212_Moving_Target_Defense_Meets_Artificial_Intelligence-Driven_Network_A_Comprehensive_Survey) [snippet-only; the attribution of the SLR statistics to this exact item is uncertain]
- **MTD with cyberdeception.** Ge, Cho, Kim and colleagues integrate MTD (network-topology shuffling) with decoys in SDN-based IoT, evaluated with graphical security models. This is proactive prevention, not quarantine. — "Proactive Defense for Internet-of-Things: Moving Target Defense with Cyberdeception", *ACM Transactions on Internet Technology* 2022, [PDF](https://people.cs.vt.edu/~irchen/ps/Ge-acmtit2022.pdf); [arXiv 2005.04220](https://arxiv.org/pdf/2005.04220) [author list beyond Ge not confirmed]
- **Quarantine.** "Quarantining Malicious IoT Devices in Intelligent Sliced Mobile Networks", arXiv:2403.19731 (2024). — [arXiv](https://arxiv.org/pdf/2403.19731) [snippet-only; method not confirmed]
- **MQTT datasets:**
  - MQTTset covers DoS, publish flood, SlowITe, malformed data and brute force, with 130,233 flooding samples.
  - MQTT-IoT-IDS2020 is mostly scans and brute force, with few DoS scenarios.
  - Older datasets are criticized as synthetic.
  - — [MQTT_UAD dataset paper, PMC12590255](https://pmc.ncbi.nlm.nih.gov/articles/PMC12590255/) [snippet-only]
- **Physical-testbed DoS dataset.** "DoS/DDoS-MQTT-IoT: A dataset for evaluating intrusions in IoT networks using the MQTT protocol", *Computer Networks* 2023 (pii S1389128623002542). It was built because real-world MQTT DoS test data were lacking. — [ScienceDirect](https://www.sciencedirect.com/science/article/pii/S1389128623002542) [snippet-only; authors not captured]
- **Real-testbed MQTT dataset with floods.** MQTTEEB-D. — [PMC12332880](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC12332880/) [snippet-only]
- **MQTT DDoS detection.** LSTM detection and classification for MQTT DDoS. — *Discover Applied Sciences* (Springer) 2026, [Springer](https://link.springer.com/article/10.1007/s42452-026-08563-8) [snippet-only]
- **eMQTT traffic generator** for IoT IDS. — *Future Internet* 18(4):203, [MDPI](https://www.mdpi.com/1999-5903/18/4/203) [snippet-only]

### Inferences
- SentinelTwin's escalating, time-boxed firewall is a lightweight, reversible quarantine. It contrasts with SDN/MTD approaches that need programmable network infrastructure.
- Being reversible matters because a misdiagnosed fault, a false positive, should not permanently isolate a device. None of the response papers found evaluates the cost of quarantining a device that was only faulty.

### Gaps
- I found no paper that evaluates MQTT broker-side rate limiting or escalating ban durations.
- I found no paper on the cost of a false-positive quarantine for fault-induced anomalies.
- I did not separately verify a 2023 automated-response survey for IoT.
