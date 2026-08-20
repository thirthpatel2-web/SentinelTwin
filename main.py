"""
main.py
-------
SentinelTwin backend. Runs an asyncio background loop that, every TICK
seconds:
  1. advances the simulated IoT network (simulator.py)
  2. scores every device for anomalies (anomaly_detector.py)
  3. diagnoses root cause for newly SUSPECT devices (diagnosis.py)
  4. updates trust scores (trust.py)
  5. drives the self-healing recovery state machine (recovery.py)
  6. broadcasts the full network snapshot + event log to every
     connected dashboard over a WebSocket

REST endpoints let the frontend (or a demo script) inject faults on
demand and fetch the current snapshot/event log.
"""

from __future__ import annotations
import asyncio
import time
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from digital_twin import DigitalTwinRegistry, DeviceState
from simulator import NetworkSimulator, FaultMode
from mqtt_bridge import start_mqtt_bridge
from security import Firewall, RateTracker, fast_attack_check
import anomaly_detector
import diagnosis
import trust
import recovery

TICK_SECONDS = 1.5

app = FastAPI(title="SentinelTwin API", version="1.0.0")
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"]
)

registry = DigitalTwinRegistry()
sim = NetworkSimulator(registry)
sim.build_default_network()
firewall = Firewall()
rate_tracker = RateTracker()

event_log: List[dict] = []
connected_sockets: List[WebSocket] = []


def _log_event(kind: str, device_id: str, message: str) -> None:
    event_log.append({
        "ts": round(time.time(), 2),
        "kind": kind,          # INFO | ANOMALY | DIAGNOSIS | RECOVERY | VERIFIED
        "device_id": device_id,
        "message": message,
    })
    if len(event_log) > 300:
        del event_log[: len(event_log) - 300]


def run_pipeline_tick() -> None:
    sim.tick_all()

    for twin in registry.all():
        prev_state = twin.state
        prev_log_len = len(twin.recovery_log)

        anomaly_detector.evaluate(twin)
        if twin.state == DeviceState.SUSPECT and prev_state != DeviceState.SUSPECT:
            _log_event("ANOMALY", twin.device_id, f"Anomaly suspected (score={twin.last_anomaly_score:.2f}).")

        # SECURITY LAYER - runs after detection, before diagnosis. A clear
        # attack pattern gets blocked immediately (fast-path); anything
        # else falls through to the normal, slower, explainable diagnosis.
        blocked_cause = fast_attack_check(twin, firewall)
        if blocked_cause is None:
            diagnosis.diagnose(twin)
        trust.update_trust(twin)
        recovery.handle_anomalous(twin, registry, sim)
        recovery.progress_recovery(twin, firewall)

        if len(twin.recovery_log) > prev_log_len:
            for new_msg in twin.recovery_log[prev_log_len:]:
                if new_msg.startswith("[FIREWALL]"):
                    kind = "FIREWALL"
                elif new_msg.startswith("[DIAGNOSIS]"):
                    kind = "DIAGNOSIS"
                else:
                    kind = "RECOVERY"
                if "VERIFIED" in new_msg:
                    kind = "VERIFIED"
                _log_event(kind, twin.device_id, new_msg.split("] ", 1)[-1])


async def broadcast_loop() -> None:
    while True:
        run_pipeline_tick()
        payload = {
            "devices": registry.snapshot(),
            "events": event_log[-40:],
            "server_time": round(time.time(), 2),
        }
        dead = []
        for ws in connected_sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in connected_sockets:
                connected_sockets.remove(ws)
        await asyncio.sleep(TICK_SECONDS)


@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(broadcast_loop())
    start_mqtt_bridge(registry, firewall, rate_tracker, log_event=_log_event)


@app.get("/api/devices")
def get_devices():
    return registry.snapshot()


@app.get("/api/events")
def get_events():
    return event_log[-100:]


class InjectRequest(BaseModel):
    fault_type: str  # HARDWARE | NETWORK | DRIFT | MALICIOUS


@app.post("/api/devices/{device_id}/inject")
def inject_fault(device_id: str, req: InjectRequest):
    sim_dev = sim.get(device_id)
    if not sim_dev:
        raise HTTPException(404, f"Unknown device {device_id}")
    try:
        mode = FaultMode(req.fault_type.upper())
    except ValueError:
        raise HTTPException(400, f"Unknown fault_type {req.fault_type}")
    if mode == FaultMode.NONE:
        raise HTTPException(400, "Use /clear to remove a fault")
    sim_dev.inject_fault(mode)
    _log_event("INFO", device_id, f"Manual fault injected: {mode.value}")
    return {"status": "ok", "device_id": device_id, "fault_type": mode.value}


@app.post("/api/devices/{device_id}/clear")
def clear_fault(device_id: str):
    sim_dev = sim.get(device_id)
    if not sim_dev:
        raise HTTPException(404, f"Unknown device {device_id}")
    sim_dev.clear_fault()
    twin = registry.get(device_id)
    if twin:
        twin.state = DeviceState.NORMAL
        twin.root_cause = None
        twin.root_cause_confidence = 0.0
        twin.history.clear()
    _log_event("INFO", device_id, "Fault manually cleared, device reset to NORMAL.")
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_sockets.append(websocket)
    try:
        await websocket.send_json({
            "devices": registry.snapshot(),
            "events": event_log[-40:],
            "server_time": round(time.time(), 2),
        })
        while True:
            await websocket.receive_text()  # keep connection alive; ignore input
    except WebSocketDisconnect:
        if websocket in connected_sockets:
            connected_sockets.remove(websocket)


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")
