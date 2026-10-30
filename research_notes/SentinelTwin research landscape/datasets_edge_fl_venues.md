# Evaluation Datasets/Metrics, Edge/TinyML & Federated Anomaly Detection, and Publication Venues for SentinelTwin

Verification legend: **[V]** = verified this session via a primary or catalog source (link given). **[TK]** = from prior knowledge, NOT re-verified this session; the report writer should either check it or flag it as unverified. Never cite a [TK] DOI without checking it on Crossref/IEEE Xplore first.

## Q1. Public datasets: content, level, labels, size, access, and fit for fault vs attack vs drift

### Takeaway
Nearly all the major IoT security datasets (CICIoT2023, CICIoMT2024, Edge-IIoTset, N-BaIoT, Bot-IoT, MQTT-IoT-IDS2020, MQTTset) are network-flow or packet level and label only benign vs attack. **TON_IoT Telemetry** and the ICS datasets (SWaT/WADI/HAI) are the only ones with sensor-value telemetry plus attack labels, and none labels benign hardware faults. Fault and drift data come from separate, unrelated corpora: Intel Berkeley Lab plus injected faults (de Bruijn et al. 2016), and UCI Gas Sensor Array Drift. SentinelTwin will need a composite or synthetic-injection evaluation.

### Cited Findings

**TON_IoT (UNSW Canberra)** [V]
- Paper: A. Alsaedi, N. Moustafa, Z. Tari, A. Mahmood, A. Anwar, "TON_IoT Telemetry Dataset: A New Generation Dataset of IoT and IIoT for Data-Driven Intrusion Detection Systems," IEEE Access, vol. 8, pp. 165130–165150, 2020, DOI 10.1109/ACCESS.2020.3022862 — [DOAJ](https://doaj.org/article/478764ecbd9b4168a278f4c7154ce88c); [RMIT repository](https://research-repository.rmit.edu.au/articles/journal_contribution/TON_IoT_Telemetry_Dataset_A_New_Generation_Dataset_of_IoT_and_IIoT_for_Data-Driven_Intrusion_Detection_Systems/27537291)
- Content: telemetry from IoT/IIoT services, plus OS logs and network traffic, collected on a medium-scale testbed at UNSW Canberra Cyber Range/IoT Labs. Labels: a binary `label` field (normal/attack) and a `type` field for attack sub-class — [DOAJ](https://doaj.org/article/478764ecbd9b4168a278f4c7154ce88c)
- Telemetry devices: fridge sensor, garage door, GPS, Modbus, weather, motion light, thermostat. This is **sensor-value level**, the closest match to SentinelTwin's DHT22 temperature/humidity stream (the weather/thermostat files) — [PMC result summary](https://pmc.ncbi.nlm.nih.gov/articles/PMC13068586/) (via search snippet; also in the Alsaedi paper)
- Access: IEEE DataPort DOI 10.21227/fesz-dm97. DataPort comments report broken or missing download links, so check current availability (UNSW research site mirror) — [IEEE DataPort](https://ieee-dataport.org/documents/toniot-datasets)
- Attack types (scanning, DoS, DDoS, ransomware, backdoor, injection, XSS, password, MITM) [TK]. No benign-fault or drift labels.

**CICIoT2023 (UNB CIC)** [V]
- E. C. P. Neto, S. Dadkhah, R. Ferreira, A. Zohourian, R. Lu, A. A. Ghorbani, "CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment," Sensors 23(13):5941, 2023, DOI 10.3390/s23135941 — [MDPI](https://www.mdpi.com/1424-8220/23/13/5941/html)
- 33 attacks in 7 categories (DDoS, DoS, Recon, Web-based, brute force, spoofing, Mirai) on a topology of 105 devices. Attacks are launched by malicious IoT devices — [DOAJ](https://doaj.org/article/0647418b437f4071b60b2765caeb3885); [UNB CIC page](https://unb.ca/cic/datasets/iotdataset-2023.html)
- Distributed as raw pcap plus flow features extracted over fixed packet windows. **Network level only**, with no sensor readings — [arXiv 2408.16021](https://arxiv.org/pdf/2408.16021)
- Its spoofing class (ARP/DNS spoofing) is network spoofing, not device-identity spoofing at the MQTT client-ID level [TK, check on CIC page].

**CICIoMT2024 (UNB CIC)** [V, from dataset pages only]
- S. Dadkhah, E. C. P. Neto, R. Ferreira, R. C. Molokwu, S. Sadeghi, A. A. Ghorbani, "CICIoMT2024: Attack Vectors in Healthcare devices — A Multi-Protocol Dataset for Assessing IoMT Device Security," Internet of Things (Elsevier), vol. 28, Dec 2024 — [UNB CIC page](https://unb.ca/cic/datasets/iomt-dataset-2024.html). Article DOI not retrieved this session [gap]. Data DOI on IEEE DataPort: 10.21227/tq0p-ag21 — [IEEE DataPort](https://ieee-dataport.org/documents/ciciomt2024wifimqtt)
- 40 devices (25 real, 15 simulated). 18 attacks in 5 classes (DDoS, DoS, Recon, MQTT, spoofing) over Wi-Fi, MQTT and Bluetooth. Captured with a network tap. Heavily dominated by UDP/ICMP floods — [UNB CIC page](https://unb.ca/cic/datasets/iomt-dataset-2024.html)
- Includes **MQTT-specific attacks** (e.g., MQTT connect flood / publish flood [TK]), which makes it relevant to SentinelTwin's "DoS flood" class. Network level only.

**Edge-IIoTset** [V]
- M. A. Ferrag, O. Friha, D. Hamouda, L. Maglaras, H. Janicke, "Edge-IIoTset: A New Comprehensive Realistic Cyber Security Dataset of IoT and IIoT Applications for Centralized and Federated Learning," IEEE Access, vol. 10, pp. 40281–40306, 2022, DOI 10.1109/ACCESS.2022.3165809 — [DOAJ](https://doaj.org/article/72942bebe6e845e3a0fbefd31f12be06); [IEEE DataPort](https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications). Co-author list beyond Ferrag is [TK]; the search said "Ferrag and four co-authors."
- 14 attacks in 5 threat categories (DoS/DDoS, information gathering, MITM, injection, malware). Seven-layer testbed (cloud, NFV, blockchain, fog, SDN, edge, IoT/IIoT perception). More than 10 device types, **including low-cost temperature/humidity sensors**, ultrasonic, water level and heart-rate sensors. Provided as CSV plus PCAP — [Napier repository](https://napier-repository.worktribe.com/output/2969370/edge-iiotset-a-new-comprehensive-realistic-cyber-security-dataset-of-iot-and-iiot-applications-for-centralized-and-federated-learning); [IEEE DataPort](https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications)
- License: free for academic research in perpetuity; commercial use needs the lead author's permission. Also mirrored on Kaggle — [IEEE DataPort](https://ieee-dataport.org/documents/edge-iiotset-new-comprehensive-realistic-cyber-security-dataset-iot-and-iiot-applications)
- Explicitly designed for **federated learning** evaluation (in its title), so useful for the FL discussion. The labelled features are network/protocol fields (including MQTT fields) [TK], not sensor-value features.

**N-BaIoT** [V for bibliographic data, no DOI retrieved]
- Y. Meidan et al., "N-BaIoT — Network-Based Detection of IoT Botnet Attacks Using Deep Autoencoders," IEEE Pervasive Computing 17(3):12–22, 2018; preprint arXiv/CoRR abs/1805.03409 — [DBLP](https://dblp.uni-trier.de/pid/200/5737.html). DOI: [TK] 10.1109/MPRV.2018.033671716? NOT VERIFIED, so look it up on IEEE Xplore.
- Content [TK]: 9 commercial IoT devices infected with Mirai and BASHLITE. 115 statistical traffic features per packet window. Hosted on the UCI ML Repository. **Network level.** Per-device benign traffic suits per-device autoencoder ("per-device twin") baselines.

**Bot-IoT** [V for existence and authorship via arXiv; venue/DOI TK]
- N. Koroniotis, N. Moustafa, E. Sitnikova, B. Turnbull, "Towards the Development of Realistic Botnet Dataset in the Internet of Things for Network Forensic Analytics: Bot-IoT Dataset," arXiv 1811.00701 — [arXiv](https://arxiv.org/pdf/1811.00701). Journal version: Future Generation Computer Systems vol. 100, 2019 [TK]. DOI 10.1016/j.future.2019.05.041 [TK, not verified this session].
- Content [TK]: more than 72M records (a 5% subset of about 3M is commonly used). DDoS, DoS, OS/service scan, keylogging, data exfiltration. Argus flow features. Extremely imbalanced, with attack traffic far outnumbering benign.

**MQTT-IoT-IDS2020** [V]
- H. Hindy, E. Bayne, M. Bures, R. Atkinson, C. Tachtatzis, X. Bellekens, "Machine Learning Based IoT Intrusion Detection System: An MQTT Case Study (MQTT-IoT-IDS2020 Dataset)," Selected Papers from the 12th International Networking Conference (INC 2020); arXiv 2006.15340 — [Strathprints](https://strathprints.strath.ac.uk/75251/); [arXiv](https://arxiv.org/pdf/2006.15340); [IEEE DataPort](https://ieee-dataport.org/open-access/mqtt-iot-ids2020-mqtt-internet-things-intrusion-detection-dataset). Author list beyond Hindy is [TK].
- Described as the first dataset to simulate an MQTT-based network. Attacks: generic scanning plus MQTT brute force — [Papers with Code](https://cs.paperswithcode.com/dataset/mqtt-iot-ids2020)
- Key limitation: it focuses on traffic between sensors, and **sensor messages are randomly generated**, so the values carry no physical meaning — [IEEE DataPort](https://ieee-dataport.org/open-access/mqtt-internet-things-intrusion-detection-dataset)

**MQTTset** [V]
- I. Vaccari, G. Chiola, M. Aiello, M. Mongelli, E. Cambiaso, "MQTTset, a New Dataset for Machine Learning Techniques on MQTT," Sensors 20(22):6578, 2020 — [PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7698741/); [MDPI](https://www.mdpi.com/1424-8220/20/22/6578/review_report). DOI 10.3390/s20226578 [TK, follows the MDPI pattern, so verify]. Co-authors [TK].
- Simulated smart home/office/building with temperature, humidity, motion and other sensors over an MQTT broker. Benign plus attack PCAPs (attacks include MQTT flood, DoS, malformed packets, brute force, SlowITe [TK]) — [PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7698741/)
- One review reports MQTTset is used in **65%** of MQTT intrusion-detection studies — [IIETA review](https://iieta.org/node/21846)
- Most protocol-faithful to SentinelTwin's MQTT/DHT22 stack, but still packet level.

**Intel Berkeley Research Lab sensor data** [TK, plus V via de Bruijn]
- [TK] 54 Mica2Dot motes recording temperature, humidity, light and voltage every 31 s, 28 Feb–5 Apr 2004, about 2.3M readings, hosted at db.csail.mit.edu/labdata. Contains **naturally occurring faults** (e.g., temperature readings above 100 °C as batteries fail, stuck values, missing data), but these are unlabelled.
- de Bruijn et al., "Benchmark Datasets for Fault Detection and Classification in Sensor Data," SENSORNETS 2016: about 5.8M points from Intel Lab, SensorScope and Smart Santander with **injected labelled faults** (random, malfunction, bias, drift, polynomial drift), plus the released injection tool — [U. Twente](https://research.utwente.nl/en/publications/benchmark-datasets-for-fault-detection-and-classification-in-sens/); [SciTePress PDF](https://www.scitepress.org/Papers/2016/56379/56379.pdf). Download availability and license not verified [gap].

**SWaT / WADI (iTrust, SUTD)** [V for access terms]
- Access by request form only. Requesters' names are published, iTrust must be credited and notified of publications, and redistribution is prohibited. WADI has no automatic download — [iTrust terms](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/terms-of-usage/); [WADI page](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/dataset-characteristics/wadi/); [summary](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/summary-of-available-datasets/)
- [TK] SWaT: 6-stage water treatment testbed, 51 sensors/actuators, 7 days normal plus 4 days with 36 attacks (Goh et al., CRITIS 2016). WADI: 123 sensors/actuators, 14 days normal plus 2 days of attacks (Ahmed et al., CySWATER 2017). **Physical-process telemetry with attack labels**, but no benign-fault labels. Known critique [TK]: some SWaT/WADI attack labels are misaligned, and WADI contains unstable/stale sensors that are often dropped.

**HAI (ETRI / NSR, Korea)** [V]
- H.-K. Shin et al., "HAI 1.0: HIL-based Augmented ICS Security Dataset," USENIX CSET 2020 — [USENIX](https://www.usenix.org/conference/cset20/presentation/shin). Maintainers ask users to cite Shin, Lee, Yun, Min, "Two ICS Security Datasets and Anomaly Detection Contest on the HIL-based Augmented ICS Testbed," CSET 2021 — [CSET21 PDF](https://cset21.isi.edu/papers/cset21-1.pdf)
- Open on GitHub (github.com/icsdataset/hai) and Kaggle. Four versions so far. Testbed: GE turbine, Emerson boiler and FESTO water treatment coupled via a dSPACE HIL simulator — [GitHub](https://github.com/icsdataset/hai)
- Attack-only labels. It is the easiest-to-access ICS telemetry option (no request form).

**UCI Gas Sensor Array Drift** [V]
- 13,910 measurements from 16 metal-oxide sensors, 6 gases, Jan 2007–Feb 2011 (36 months), 128 features, organised in 10 batches. Built for drift-compensation studies. License **CC BY 4.0**. Companion paper: A. Vergara et al., "Chemical gas sensor drift compensation using classifier ensembles," Sensors and Actuators B: Chemical, 2012 — [UCI #224](https://archive.ics.uci.edu/dataset/224/gas+sensor+array+drift+dataset); concentration-label variant [UCI #270](https://archive.ics.uci.edu/dataset/270/gas+sensor+array+drift+dataset+at+different+concentrations). DOI 10.1016/j.snb.2012.01.074 [TK].
- Fit: real long-term sensor drift, but it is a gas-classification task, not a time-series temperature/humidity stream, so it transfers only loosely to DHT22. Used for IoT drift ML in Zheng & Paiva, arXiv 2109.04356 — [arXiv](https://arxiv.org/pdf/2109.04356)

**Other fault/drift-relevant resources found**
- Oikonomou et al., SPICES workshop @ EWSN 2023: real-world office IoT dataset for **concept drift, including anomalous drift caused by attacks**. A close conceptual neighbour to SentinelTwin's goal — [EWSN 2023 PDF](https://www.ewsn.org/file-repository/ewsn2023/SPICES%202023-final8390.pdf). Exact title and author list not verified [gap].
- SensorFault-Bench (arXiv 2605.10822, 2026): 8 fault scenarios in value, timing and availability groups, including drift and spike, injected into forecasting inputs — [arXiv](https://arxiv.org/pdf/2605.10822). Preprint only.
- "Internet of Things Fault Detection and Classification via Multitask Learning," arXiv 2307.01234 — [arXiv](https://arxiv.org/pdf/2307.01234) (details not read).
- Attarha & Förster, IFIP WONS 2024: review of sensor fault models (bias, drift, noise, gain, outliers, stuck) with a composite model. Useful for **justifying a fault-injection taxonomy** — [IFIP DL PDF](https://dl.ifip.org/db/conf/wons/wons2024/1570970228.pdf)
- DAD: "Annotated Dataset for Anomaly Detection in a Data Center with IoT Sensors" (2020), labelled traffic anomalies — [PMC](https://www.ncbi.nlm.nih.gov/pmc/articles/PMC7374380/)

**Known criticisms**
- A 2025 critical review (Computer Networks and Communications, Wiser Pub) says BoT-IoT, N-BaIoT and CICIoT2023 routinely yield near-99% accuracy. It argues that testbed configuration and feature choices are overlooked, and that standardisation is needed for reproducibility — [Wiser Pub](https://ojs.wiserpub.com/index.php/CNC/article/view/7228)
- "Unmasking Shortcut Learning in IoT Intrusion Detection: A Forensic, Multi-Paradigm Evaluation of Feature Dependence and Data Leakage," arXiv 2609.28725 (2026). Directly addresses shortcut features and leakage — [arXiv](https://arxiv.org/pdf/2609.28725). Findings not read [gap].
- Florida Atlantic University thesis on Bot-IoT pitfalls (2021) — [FAU](https://fau.isle.flvc.org/node/42769)
- MQTT-IoT-IDS2020 uses randomly generated sensor payloads — [IEEE DataPort](https://ieee-dataport.org/open-access/mqtt-internet-things-intrusion-detection-dataset)
- TON_IoT download links reported broken on DataPort — [IEEE DataPort](https://ieee-dataport.org/documents/toniot-datasets)
- CICIoMT2024 is dominated by UDP/ICMP floods, i.e. class imbalance — [UNB CIC](https://unb.ca/cic/datasets/iomt-dataset-2024.html)
- [TK] Bot-IoT critiques commonly cited: extreme class imbalance, and identifiers such as IP addresses or sequence numbers that leak labels. N-BaIoT: trivially separable, with many papers reporting about 100%. These are commonly made points, but no specific source was retrieved this session.

### Inferences
- **Recommended composite evaluation design.** (a) Attack disambiguation: replay TON_IoT weather/thermostat telemetry (value-level FDI/tampering) and MQTTset or CICIoMT2024 MQTT floods (DoS) through SentinelTwin's MQTT ingest. (b) Fault/drift: Intel Lab data with de Bruijn-style injected faults (stuck, spike, bias, drift, dropout). (c) A testbed experiment on the real ESP32/DHT22 rig with scripted fault, attack and drift injection and ground-truth timestamps. The testbed trace is the only place all three classes coexist on the same telemetry. Releasing it would be a contribution in its own right.
- Network-flow datasets (CICIoT2023, Bot-IoT, N-BaIoT) are a poor fit for a value-level, per-device-twin detector. Cite them as related work, and maybe use them for the security-layer DoS/spoofing detector only.
- Report results per root-cause class (macro-F1) and on temporally split data, so reviewers aware of the shortcut-learning critiques don't dismiss near-100% accuracy.

### Gaps
- Exact sizes and record counts for TON_IoT telemetry files, CICIoT2023 (about 46.7M flows [TK]) and Edge-IIoTset were not retrieved this session.
- DOIs for N-BaIoT, Bot-IoT (FGCS), MQTTset, the CICIoMT2024 article and the Gas Drift paper are unverified [TK].
- Intel Lab download page and license not checked this session.
- Licenses for CICIoT2023 and CICIoMT2024 not retrieved. CIC datasets usually require citation, terms [TK].

## Q2. Is there a public benchmark jointly labelling benign faults, drift AND attacks on the same IoT telemetry?

### Takeaway
No such dataset was found. A targeted search ("IoT dataset labeled sensor faults and cyberattacks distinguishing fault from attack") returned only attack-only network datasets. Fault benchmarks (de Bruijn 2016, SensorFault-Bench 2026) contain no attacks. This looks like a genuine gap SentinelTwin can claim, worded carefully as "to our knowledge."

### Cited Findings
- Search for joint fault-and-attack-labelled IoT datasets returned only attack-labelled flow datasets (CyberFlowIoT-GICAP 2026, IoT-23, CIC TabularIoTAttack-2024, TON_IoT). None has a sensor-fault class — [CyberFlowIoT PMC](https://pmc.ncbi.nlm.nih.gov/articles/PMC13068586/); [CIC Tabular IoT Attack 2024](https://www.unb.ca/cic/datasets/tabular-iot-attack-2024.html)
- Fault benchmarks contain injected faults only (random, malfunction, bias, drift, polynomial drift), with no adversarial class — [de Bruijn et al. 2016](https://research.utwente.nl/en/publications/benchmark-datasets-for-fault-detection-and-classification-in-sens/)
- The nearest neighbour is the SPICES/EWSN 2023 office IoT concept-drift dataset, which includes "anomalous drift" from attacks but no labelled hardware faults — [EWSN 2023](https://www.ewsn.org/file-repository/ewsn2023/SPICES%202023-final8390.pdf)

### Inferences
- The ICS datasets (SWaT/WADI/HAI) come closest structurally (physical telemetry plus attacks). A common workaround in the literature is to inject synthetic faults into them, which SentinelTwin could also do for an external-validity experiment.
- Contribution framing: "a labelled fault/attack/drift trace from a physical ESP32-DHT22 testbed plus an injection script" is publishable as a dataset artefact (e.g., in Data in Brief or IEEE DataPort).

### Gaps
- The search can't prove absence. A Google Scholar search of "fault" AND "attack" AND "IoT" AND "dataset" on IEEE DataPort, Kaggle and Zenodo is advisable before claiming novelty. Also check whether ICS works on "fault vs attack discrimination" (e.g., power grid PMU datasets, Mississippi State/ORNL power system attack datasets [TK], which include natural faults) partially cover this. The ORNL/MSU power-system dataset labels "natural events" (short-circuit faults, maintenance) separately from attacks, which would partially contradict an absolute "no dataset" claim [TK — verify].

## Q3. Metrics for self-healing/recovery systems

### Takeaway
MTTD, MTTR, availability, recovery success rate, FPR and per-class confusion matrices are standard, but **definitions vary across papers** (especially MTTR), and several recent arXiv papers report "aspirational" rather than measured numbers. SentinelTwin should define each metric formally with timestamps (onset t0, detection td, diagnosis tg, recovery-start tr, verified-restore tv) and measure them on real injections.

### Cited Findings
- MTTD = delay between true failure onset and detection ("blind window") — [arXiv 2512.22721](https://arxiv.org/pdf/2512.22721) (via search summary)
- MTTR is defined inconsistently: detection-to-recovery in some papers, expected repair time after failure in others, and "mean time to resolution" in network operations (alongside MTTA and MTBF) — [ManageEngine](https://www.manageengine.com/network-monitoring/tech-topics/key-network-availability-metrics.md); [arXiv 2512.22721](https://arxiv.org/pdf/2512.22721)
- An IoMT digital-twin paper splits recovery into phases: Mean Time to Contain (detection to quarantine) and Mean Time to Recover (containment to restoration) — [arXiv 2606.21513](https://arxiv.org/pdf/2606.21513)
- Caution: a reported 99.8% recovery success rate and 720 h MTBF were described by a companion paper from overlapping authors as **aspirational targets, not validated** without long-duration deployment — [arXiv 2606.21422](https://arxiv.org/pdf/2606.21422); [arXiv 2606.21513](https://arxiv.org/pdf/2606.21513)
- Q-learning self-healing in simulation (50–500 nodes) cut mean recovery time by 51.9% vs random and 32.8% vs rule-based in a multiple-failure scenario. This is an example of comparative MTTR reporting against baselines — [Gazi Univ. J. Sci. Part A, DOI 10.54287/gujsa.1914900](https://www.citedrive.com/en/discovery/reinforcement-learning-based-self-healing-framework-in-iot-sensor-networks/)
- Fault-injection evaluation designs compare (i) a fault-free baseline, (ii) faults without self-healing, and (iii) faults with self-healing — [arXiv 2302.05336](https://arxiv.org/pdf/2302.05336)
- Threshold-triggered DQN self-healing for SD-IIoT edge networks (2025) is another comparator — [arXiv 2512.14297](https://arxiv.org/pdf/2512.14297)
- Learning recovery strategies for self-healing reactive systems — [arXiv 2401.12405](https://arxiv.org/pdf/2401.12405)

### Inferences
- Suggested metric set for SentinelTwin:
  - Detection: precision, recall, F1, FPR per hour, MTTD (median and p95).
  - Diagnosis: per-root-cause confusion matrix and macro-F1 over {hardware fault, network failure, drift, FDI/tamper, DoS, spoofing}, and time-to-diagnose.
  - Recovery: recovery success rate (verified restore / attempts), MTTR (td→tv), false-recovery rate (actions triggered on benign events), and availability = uptime/(uptime+downtime) over the run.
  - Trust: trust-score separation (AUC between honest and malicious devices), and time for trust to drop below the quarantine threshold.
  - Overhead: CPU, RAM and latency per message.
- Report baselines: no-healing, a naive restart-on-any-anomaly policy, and threshold-only detection. Be explicit that results come from a testbed, not a deployment, to avoid the "aspirational number" trap.

### Gaps
- No authoritative standard (e.g., IEEE/ISO) defining MTTR for IoT self-healing was found this session. IEC 60050-192 / ITIL definitions could be cited [TK].

## Q4. Edge/TinyML anomaly detection on ESP32 and microcontrollers (2022–2026)

### Takeaway
Autoencoder, isolation-forest and simple statistical detectors run on ESP32-class MCUs at roughly tens of KB of memory and millisecond-scale latency. Statistical z-score methods are in the microsecond range. Most work targets vibration, ECG or industrial signals rather than security, and peer-reviewed 2023–2024 ESP32 security-AD numbers were scarce.

### Cited Findings
- ArrythML (arXiv 2606.02256, 2026 preprint): an autoencoder on ESP32-S3 (512 KB SRAM budget). The DNN AE is about 180 KB with **9 ms** inference. The INT8 CNN AE is about 42 KB, and its on-device F1 dropped to about 65.7% after quantization — [arXiv](https://arxiv.org/html/2606.02256v1)
- Motor-vibration anomaly detection on a XIAO ESP32S3 with Edge Impulse (quantised and pruned): **25 ms** average inference vs Random Forest 60 ms and SVM 78 ms — [Discover IoT (Springer), 2025](https://link.springer.com/article/10.1007/s43926-025-00142-4)
- An adaptable, unsupervised TinyML AD system for extreme industrial environments stores an Isolation Forest as JSON in ESP32 flash. Memory fell from about 800 KB (50 trees) to **84 KB** after redesign — [Sensors, PMC9962960](https://pmc.ncbi.nlm.nih.gov/articles/PMC9962960/) (published 2023 [TK year])
- A z-score TinyML anomaly detector on STM32 power side-channel data runs in about **20–40 µs** — [arXiv 2604.08581](https://arxiv.org/pdf/2604.08581)
- TinyAD: memory-efficient anomaly detection for IIoT time series (arXiv 2303.03611, 2023) — [arXiv](https://arxiv.org/pdf/2303.03611)
- Modified overcomplete autoencoder that trains and infers on ESP32-CAM (no numbers in snippet) — [ResearchGate](https://www.researchgate.net/publication/384133067_Modified_Over-complete_Autoencoder_for_Anomaly_Detection_based_on_TinyML)
- TinyML for cybersecurity in EV charging infrastructure (arXiv 2404.16894) — [arXiv](https://arxiv.org/pdf/2404.16894)
- Real-time ML for embedded anomaly detection (arXiv 2512.19383) — [arXiv](https://arxiv.org/pdf/2512.19383)

### Inferences
- SentinelTwin's statistical (z-score/EWMA-style) explainable detector is cheap enough to run **on the ESP32 itself** as a first-line check (µs range per the STM32 data point). That supports a "hybrid edge plus twin" architecture argument and gives a cheap ablation: on-device vs server-side detection latency.
- Limitations to state: quantisation degrades accuracy (ArrythML), on-device models are usually trained offline, there is no on-device drift adaptation, and an on-device detector can be bypassed if the device itself is compromised. That last point is an argument for SentinelTwin's server-side security layer.

### Gaps
- No peer-reviewed 2023–2024 paper reporting ESP32 **intrusion/anomaly** detection with full accuracy, latency and memory triples was found this session. Many of the strongest numbers are 2025–2026 preprints.

## Q5. Federated learning for IoT anomaly/intrusion detection: key works and open problems

### Takeaway
FL-IDS for IoT is well surveyed. Recurrent open problems are non-IID client data (weight divergence), poisoning/backdoor attacks by malicious clients, heterogeneity, and the lack of standardised benchmarks. Edge-IIoTset is the dataset explicitly built for FL evaluation.

### Cited Findings
- Campos et al., "Evaluating Federated Learning for Intrusion Detection in Internet of Things: Review and Challenges" (arXiv 2108.00974; published in Computer Networks [TK: vol. 203, 2022]). Quantifies the effect of non-IID data across aggregation methods using IBMFL — [ar5iv](https://ar5iv.labs.arxiv.org/html/2108.00974)
- Belenguer et al., FL review for IoT IDS (arXiv 2204.12443, 2022). Argues for evaluation standardisation; the venue was given as IEEE IoT Journal in the search summary [TK, verify] — [arXiv](https://www.arxiv.org/pdf/2204.12443)
- Isma'ila et al., "Review on Approaches of Federated Modeling in Anomaly-Based Intrusion Detection for IoT Devices," IEEE Access 2024. Covers non-IID weight divergence, datasets, aggregation and metrics — [UTP KHub](https://khub.utp.edu.my/scholars/20143/)
- Systematic review of 140 studies on poisoning defences in IoT FL: proposes a taxonomy (standalone, hybrid, multi-combined) and finds a significant gap between idealised experimental assumptions and IoT realities — [Research Square preprint](https://www.researchsquare.com/article/rs-9754545/v1) (year and peer-review status unverified)
- Matthew & John-Dewole (2025) survey of FL-IDS in Cloud–IoT: poisoning, inference attacks, client heterogeneity, non-IID, no standard benchmarks — [LCU journal](https://journals.lcu.edu.ng/index.php/LCUPGMCP/article/view/1741) (low-visibility venue, so cite with caution)
- Gad et al. (arXiv 2511.16822, Nov 2025): FedAvg vs FedProx vs SCAFFOLD on CICIoT2023 under non-IID partitions — [arXiv](https://arxiv.org/html/2511.16822v1)
- Edge-IIoTset was designed for centralised and federated learning — [IEEE Access 2022](https://doaj.org/article/72942bebe6e845e3a0fbefd31f12be06)
- [TK] Canonical earlier works: Nguyen et al., "DÏoT: A Federated Self-learning Anomaly Detection System for IoT," IEEE ICDCS 2019. Rey et al., "Federated learning for malware detection in IoT devices," Computer Networks 2022 (on N-BaIoT, with adversarial clients). Not re-verified.

### Inferences
- SentinelTwin's per-device twins map naturally onto FL clients (each twin learns local normal behaviour). Its trust scoring could double as a **robust-aggregation weight** (down-weighting low-trust clients), which addresses poisoning. This is a credible "future work" or extension direction.
- Non-IID is intrinsic: different rooms or sensors have different baselines, which argues for personalised FL (FedProx/per-client heads) rather than plain FedAvg.

### Gaps
- No 2023–2026 paper combining FL, digital twins and fault-vs-attack diagnosis was found this session (not searched specifically).

## Q6. Concept/data drift adaptation in IoT ML

### Takeaway
ADWIN, Page-Hinkley and DDM (available in Python's River library) are the standard drift detectors, combined with adaptive learners such as Hoeffding Adaptive Trees. The IoT-specific evidence is mostly small studies. The key unaddressed issue for SentinelTwin is distinguishing **benign sensor drift from slow adversarial manipulation** (e.g., gradual FDI), which drift detectors alone can't do.

### Cited Findings
- PWPAE (Performance-Weighted Probability Averaging Ensemble) for IoT anomaly detection with concept drift. Uses River with ADWIN and DDM; evaluated on IoTID20 and CICIDS2017 — [GitHub Western-OC2-Lab](https://fr.github.com/Western-OC2-Lab/PWPAE-Concept-Drift-Detection-and-Adaptation). [TK] Paper: L. Yang, D. M. Manias, A. Shami, "PWPAE: An Ensemble Framework for Concept Drift Adaptation in IoT Data Streams," IEEE GLOBECOM 2021.
- ADWIN vs Page-Hinkley with SGD on streaming IoT sensor data: ADWIN was more sensitive and outperformed PH on that single dataset — [UPH Medan journal](https://ejournal-medan.uph.edu/isd/article/download/456/259/1326) (low-tier venue; preliminary)
- Hoeffding Adaptive Tree plus ADWIN for NIDS, evaluated prequentially on UNSW-NB15 (2026) — [Smart Technologies Journal](https://stj.aiu.kz/index.php/stj/en/article/view/13)
- Unsupervised drift detection for online IDS building on ADWIN-U, to reduce labelling cost (CEUR-WS Vol. 4198) — [CEUR](https://ceur-ws.org/Vol-4198/paper54.pdf)
- Online learning is memory- and time-efficient for resource-constrained IoT perception layers — [Staffordshire eprint](https://eprints.staffs.ac.uk/6083)
- "Binary Anomaly Detection in Streaming IoT Traffic under Concept Drift" (arXiv 2510.27304) uses MQTT datasets — [arXiv](https://arxiv.org/pdf/2510.27304)
- Zheng & Paiva, "Assessing Machine Learning Approaches to Address IoT Sensor Drift" (arXiv 2109.04356) on the UCI gas drift data — [arXiv](https://arxiv.org/pdf/2109.04356)

### Inferences
- For SentinelTwin: use Page-Hinkley/ADWIN on twin residuals to flag drift, then apply disambiguation rules: drift is slow, monotone and consistent with neighbouring or redundant sensors, while FDI is inconsistent with physics or neighbours and often coincides with security-layer signals. Evaluate on injected drift (Intel Lab plus de Bruijn-style drift) vs injected slow FDI. That is where the paper's novelty is measurable.
- Seminal references to cite [TK]: Bifet & Gavaldà, "Learning from Time-Changing Data with Adaptive Windowing," SIAM SDM 2007 (ADWIN). Page, "Continuous Inspection Schemes," Biometrika 1954 (Page-Hinkley/CUSUM). Montiel et al., "River: machine learning for streaming data in Python," JMLR 22(110), 2021. Gama et al., "A survey on concept drift adaptation," ACM Computing Surveys 46(4), 2014.

### Gaps
- High-quality 2023–2026 peer-reviewed IoT drift-adaptation studies were thin in the results. Most found were preprints or low-tier venues.

## Q7. Publication venues for a student team, and predatory-venue risks

### Takeaway
Realistic tiers: (1) a stretch journal, IEEE IoT Journal (IF about 8–9, roughly 20% acceptance [estimate]), which needs strong evaluation; (2) mid-tier journals with broader acceptance, e.g. IEEE Access, MDPI Sensors, Elsevier Internet of Things, Computer Networks, FGCS; (3) IEEE conferences suited to prototypes, e.g. IEEE WF-IoT, COMSNETS (and its student/demo tracks), IEEE INDICON, NOMS/CNSM demo or short-paper tracks. Check indexing (Scopus/WoS) and use Think.Check.Submit to avoid predatory or "hijacked" journals and conference-mill events.

### Cited Findings
- IEEE Internet of Things Journal: JCR 2023 IF 8.2, JCR 2024 IF 8.9, 5-year IF 9.6. Average 6.9 weeks to first decision and 14.5 weeks to e-publication — [IEEE IoT-J site](https://ieee-iotj.org/history/impactfactorsperyear/); [IEEE IoT-J](https://ieee-iotj.org/). Acceptance about 20% according to a third-party guide (estimate, not official) — [Manusights](https://manusights.com/blog/ieee-internet-of-things-journal-submission-guide)
- [TK] IEEE Access: fully open access, binary accept/reject review with about 4–6 weeks to decision. APC about US$1,995 (check current). Acceptance roughly 25–30% (unofficial). WoS/Scopus indexed. Fast, but has a reputation as a "mega-journal."
- [TK] MDPI Sensors: open access, APC about CHF 2,600, WoS and Scopus indexed, fast turnaround. Criticism of MDPI's model: M. Á. Oviedo-García, "Journal citation reports and the definition of a predatory journal: The case of MDPI," Research Evaluation 30(3), 2021. That paper itself received an expression of concern and is contested. MDPI is generally regarded as legitimate but "high-volume," and some institutions or national lists downgrade some MDPI titles. Not verified this session.
- [TK] Elsevier: Future Generation Computer Systems (IF about 6–7), Computer Networks (IF about 4–5), Internet of Things (Elsevier, IF about 6). Peer-reviewed subscription/hybrid journals with harder review, where evaluation rigour matters most.
- [TK] Conferences: IEEE NOMS (even years) and CNSM (annual), network/service management, ideal for "self-healing" and "autonomic management" themes, with demo and short-paper tracks. IEEE WF-IoT (World Forum on IoT), broad IoT scope and friendly to prototypes. COMSNETS (Bengaluru, January), Scopus/IEEE Xplore, with workshops and a graduate forum. IEEE INDICON (IEEE India Council flagship), suited to student teams in India. All published in IEEE Xplore. Acceptance rates not verified this session.

### Inferences
- Recommended path for a student team: submit the prototype plus composite evaluation to **IEEE WF-IoT or COMSNETS (main or workshop)** or **CNSM/NOMS short/demo**, then extend into a journal version (Elsevier Internet of Things, IEEE Access, or Sensors) with the released dataset. IEEE IoT-J realistically needs multi-dataset evaluation, strong baselines and novelty beyond a rule-based diagnoser.
- Predatory-risk checklist: confirm the journal on Scopus Sources / Clarivate Master Journal List directly (hijacked clones copy names); avoid unsolicited "call for papers" emails promising 1–2 week acceptance; check that conference proceedings appear in IEEE Xplore under a real IEEE conference record number; check the DOAJ listing for OA journals; use thinkchecksubmit.org. Some low-visibility venues surfaced in this research (e.g., LCU Postgraduate Serials, some regional journals) shouldn't be used as primary citations.

### Gaps
- IEEE Access, Sensors, FGCS and Computer Networks acceptance rates, impact factors and APCs were not retrieved this session (the search returned only IoT-J data).
- Current status of MDPI in national rating lists (e.g., Finland's JUFO, China's CAS warning list) not verified.
- Conference acceptance rates for WF-IoT, COMSNETS, INDICON, NOMS and CNSM not verified, and 2027 deadlines not checked.
