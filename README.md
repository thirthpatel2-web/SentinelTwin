# SentinelTwin
### AI-Driven Self-Healing IoT Network Using Digital Twin Technology

A working prototype of the pipeline:

```
Monitor → Predict/Detect → Security Layer → Diagnose → Respond → Recover → Verify
```

instead of the conventional IoT flow (`Monitor → Detect failure → Human
intervention → Repair`).

---

## What's actually implemented

A simulated IoT network of **temperature, humidity, and motion sensors
plus gateways** across 3 zones, each with a **Digital Twin** (live
software mirror of its state, history, trust score, and lifecycle).
Every 1.5s tick:

1. **Simulator** (`simulator.py`) generates realistic correlated
   telemetry per device, and can be pushed into 4 fault modes:
   `HARDWARE`, `NETWORK`, `DRIFT`, `MALICIOUS`.
2. **Anomaly Detector** (`anomaly_detector.py`) scores every device
   using two complementary, fully-explainable statistics — no
   black-box model:
   - a **rolling z-score** against the last ~9 ticks (catches sudden
     changes)
   - a **frozen calibration baseline** z-score captured once early in
     the device's life (catches slow drift that a rolling window can't
     see, since the window itself drifts along with the signal)
3. **Security Layer** (`security.py`) — sits between detection and
   diagnosis. See below.
4. **Diagnosis** (`diagnosis.py`) turns a flagged device into one of
   four explained root causes by reading the *shape* of those two
   scores — e.g. one metric far from its original baseline but moving
   gradually → `SENSOR_DRIFT`.
5. **Trust** (`trust.py`) maintains an exponential-moving-average trust
   score per device, with an extra penalty for tampering.
6. **Recovery** (`recovery.py`) autonomously responds per root cause —
   isolate + reroute, isolate + activate backup, soft recalibrate, or
   quarantine — then **verifies** the fix over several clean ticks
   before marking the device `RECOVERED`.
7. **main.py** runs this loop over WebSocket, broadcasting the full
   network state + a live explainable event log to the dashboard.
8. **static/index.html** is a dark-themed real-time dashboard: device
   cards grouped by zone, trust bars, live root-cause explanations,
   reroute arrows, firewall-blocked badges, and a scrolling event log —
   plus buttons to inject any of the 4 fault types live for a demo.

## Root-cause classes (diagnosis.py — non-adversarial faults)

| Root cause | Signature | Recovery action |
|---|---|---|
| `HARDWARE_FAULT` | one metric jumps instantly, everything else (incl. signal) normal | isolate + activate backup device |
| `NETWORK_FAILURE` | signal_strength collapses, packet_loss rises | isolate + reroute data to standby |
| `SENSOR_DRIFT` | one metric wanders far from its *original* calibration baseline, but tick-to-tick change is small | soft recalibrate in place (no isolation) |

## Security Layer (security.py — adversarial/attack classes)

Positioned explicitly between detection and diagnosis, because the
two should not be the same step (see Research Foundation below). It
runs a **fast, aggressive** attack check immediately after a device is
flagged `SUSPECT`, before the slower, explainable diagnosis stage even
runs. If it finds a clear attack signature, it **firewalls the device
— a real, time-boxed block that other code actually enforces** —
instead of waiting for full diagnosis.

| Attack | How it's detected | Where it's enforced |
|---|---|---|
| `MALICIOUS_TAMPERING` (fast-path) | 2+ metrics jump instantly past a strict z-score threshold in a single tick | `security.fast_attack_check()`, called every tick in `main.py` before `diagnosis.diagnose()` |
| `DOS_FLOOD_ATTACK` | Message rate for a device exceeds ~5× its own learned normal cadence | `security.enforce_on_ingest()`, called by `mqtt_bridge.py` **before a message is ever written to the twin** |
| `IDENTITY_SPOOFING` | A device_id publishes a `device_type` that conflicts with what it registered as | Same ingestion point in `mqtt_bridge.py` |

The firewall (`security.Firewall`) blocks a device_id for a time-boxed
window that **escalates on repeat offenses** (30s → 60s → 120s →
240s, capped at 300s). While blocked:
- A real MQTT device's messages are silently dropped at the bridge —
  the connection is actually cut, not just visually marked.
- A simulated device is isolated the same way `ISOLATED` already stops
  the simulator feed.
- Recovery's verification clock (`recovery.progress_recovery`)
  **can't even start counting clean ticks until the firewall block
  itself expires** — the security layer's decision holds priority over
  the ordinary recovery loop.

Tested and verified live: injected a fast malicious spoof on a
simulated device (correctly firewalled before diagnosis ran), flooded
a real MQTT topic via `tools/test_publisher.py --fault flood`
(correctly detected and blocked), and published a real
identity-mismatched MQTT message via `mosquitto_pub` (correctly
detected and blocked) — all against a locally running Mosquitto broker.

## Research Foundation

The Security Layer's design choices are grounded in current published
work on digital-twin-based IoT security, not invented from scratch:

- **Splitting fast detection from slow diagnosis is empirically
  better than one combined stage.** A digital-twin + blockchain IoT
  security study (*Causio-TwinChain*, Scientific Reports) paired a
  fast anomaly-flagging stage with a separate causal root-cause stage
  and measured a 68% cut in mean time-to-diagnosis and a 22% drop in
  false positives versus combining both into one step — directly
  motivating why the security layer runs *before*, not *inside*,
  `diagnosis.py`.
- **Simple statistical rate-monitoring is a legitimate first line of
  defense for digital-twin traffic specifically**, because that
  traffic is cyclical and predictable (periodic sensor reports),
  unlike general IT network traffic. A 2025 data-rate-monitoring study
  for digital twin communication validated a lightweight statistical
  threshold approach and found DoS attacks produced roughly a 50×
  spike in packet rate against the normal baseline — this is exactly
  what `security.RateTracker` implements (learn a per-device baseline
  cadence, flag a large multiple of it), rather than reaching for a
  trained ML model where simple statistics are already sufficient and
  fully explainable.
- **Digital twins are well suited to catching a compromised node that
  either emits false data or is used to attack its neighbors** (IEEE,
  fog-based digital twin "Compromised Node Detection" architecture) —
  motivating why a flagged device here is firewalled off the network
  entirely, not just flagged for review.
- A broader Digital Twin + IDS study (Snort + Eclipse Ditto on a
  Raspberry Pi, testing real Hping3 flood attacks and NMAP scans)
  found flood-style attacks were reliably caught by rate-based methods
  while reconnaissance-style scans were not — an honest limitation
  that also applies here (see "Ideas to extend further").

## Run it

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Open `http://localhost:8000`. The network starts clean; give it
~15 seconds to build a calibration baseline, then click any of the
`HW fault / Net fault / Drift / Spoof` buttons on a device card to
watch the full detect → security → diagnose → recover → verify loop
run live in the event log.

## API

- `GET /api/devices` — current snapshot of every device's Digital Twin
- `GET /api/events` — recent explainable event log
- `POST /api/devices/{id}/inject` — body `{"fault_type": "HARDWARE|NETWORK|DRIFT|MALICIOUS"}`
- `POST /api/devices/{id}/clear` — manually reset a device
- `WS /ws` — live snapshot + event stream (what the dashboard uses)

## Real hardware bridge (optional, tested)

SentinelTwin doesn't just simulate — it can genuinely ingest telemetry
from a real physical device over MQTT, through the exact same Digital
Twin pipeline (same anomaly detector, security layer, diagnosis rules,
trust scoring, and recovery engine) as the simulated fleet. This was
built and verified end-to-end against a real local MQTT broker: a live
device connects, gets diagnosed on a real induced fault, and **fails
over to a simulated standby device** — proof the pipeline is genuinely
data-source-agnostic, not hardcoded to the simulator.

**Files:**
- `mqtt_bridge.py` — subscribes to `sentineltwin/<device_id>/telemetry`,
  enforces the security layer's firewall at the point of ingestion, and
  feeds allowed messages into the same `DeviceTwin.push_reading()` the
  simulator uses. Devices registered this way are tagged `is_real: true`
  and show a "LIVE HARDWARE" badge on the dashboard.
- `security.py` — the Firewall + RateTracker + fast attack-pattern
  checks described above.
- `arduino/sentineltwin_esp32.ino` — ESP32 + DHT22 sketch that publishes
  real temperature/humidity/WiFi-RSSI-as-signal-strength readings on
  the wire format the bridge expects. Edit the WiFi/broker constants at
  the top and flash it.
- `tools/test_publisher.py` — a CLI MQTT publisher that lets you verify
  the bridge (and even simulate a fault, or a flood attack, on a "real"
  device) without owning an ESP32 yet:
  `python tools/test_publisher.py --fault network`
  `python tools/test_publisher.py --fault flood`

**To run it:**
```bash
# 1. Start a local broker (one-time install)
sudo apt-get install mosquitto mosquitto-clients
mosquitto -d -p 1883

# 2. Start SentinelTwin as usual — the bridge starts automatically
#    and just logs a message if no broker is found (fully optional)
uvicorn main:app --reload --port 8000

# 3a. Either flash the ESP32 sketch pointed at this machine's IP, or
# 3b. Simulate one with the test publisher:
python tools/test_publisher.py --device-id REAL-TEMP-01
```
The device appears on the dashboard tagged LIVE HARDWARE within a
couple of seconds and is covered by the same simulated standby pool
(`BKP-TEMP-*` etc.) as every other device.

## Ideas to extend further (not yet built)

- Swap the rolling/baseline z-score for an `IsolationForest` (scikit-learn)
  per device as a stated "AI" upgrade, keeping the current rule-engine
  as the explainability layer on top of it.
- Reconnaissance-style scan detection (port/topic enumeration) — the
  literature notes this is a known weak spot for rate-based IDS
  approaches like the one used here.
- A network topology graph view (D3/force-directed) instead of the
  zone-grid, to visualize reroute paths.
- Persist event history to SQLite so a "post-incident report" can be
  generated per device.
- A confusion-matrix style accuracy report: inject N random faults,
  compare diagnosed cause vs. ground truth, to quote a detection
  accuracy % in the PPT.
