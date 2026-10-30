"""
main.py
-------
SentinelTwin live server. Runs the SentinelEngine (engine.py) on wall-clock
time, one tick every 1.5 s, and broadcasts the network snapshot, the
explainable event log and the incident timeline to every dashboard over a
WebSocket. Real hardware joins through the MQTT bridge (mqtt_bridge.py)
and goes through exactly the same ingestion and pipeline.

    uvicorn main:app --reload --port 8000
"""

from __future__ import annotations
import asyncio
import os
from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from engine import SentinelEngine
from mqtt_bridge import start_mqtt_bridge
from simulator import FaultMode, TICK_SECONDS

app = FastAPI(title="SentinelTwin API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

engine = SentinelEngine(seed=int(os.environ["SENTINELTWIN_SEED"]) if "SENTINELTWIN_SEED" in os.environ else None)
connected_sockets: List[WebSocket] = []


async def broadcast_loop() -> None:
    while True:
        engine.tick()
        payload = engine.snapshot()
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
    start_mqtt_bridge(engine, log_event=engine.log_event)


@app.get("/api/devices")
def get_devices():
    return engine.registry.snapshot()


@app.get("/api/events")
def get_events():
    return engine.events[-100:]


@app.get("/api/incidents")
def get_incidents():
    return engine.incidents.recent(100)


class InjectRequest(BaseModel):
    fault_type: str                     # HARDWARE|STUCK|DROPOUT|NETWORK|GATEWAY|DRIFT|TAMPER|TAMPER_RAMP|ON_OFF|FLOOD|SPOOF
    attacker: Optional[str] = None      # TAMPER_RAMP: fabricate | inpath | rogue | compromised
    slope: Optional[float] = None       # TAMPER_RAMP / DRIFT speed (noise sigma per reading)


@app.post("/api/devices/{device_id}/inject")
def inject_fault(device_id: str, req: InjectRequest):
    try:
        mode = FaultMode(req.fault_type.upper())
    except ValueError:
        raise HTTPException(400, f"Unknown fault_type {req.fault_type}")
    if mode == FaultMode.NONE:
        raise HTTPException(400, "Use /clear to remove a fault")
    params = {}
    if req.attacker:
        params["attacker"] = req.attacker
    if req.slope is not None:
        params["slope" if mode == FaultMode.TAMPER_RAMP else "rate"] = req.slope
    try:
        engine.inject(device_id, mode.value, **params)
    except KeyError:
        raise HTTPException(404, f"Unknown simulated device {device_id}")
    return {"status": "ok", "device_id": device_id, "fault_type": mode.value, **params}


@app.post("/api/devices/{device_id}/clear")
def clear_fault(device_id: str):
    if engine.registry.get(device_id) is None:
        raise HTTPException(404, f"Unknown device {device_id}")
    engine.clear(device_id)
    return {"status": "ok"}


class ZoneEventRequest(BaseModel):
    magnitude_t: float = 5.0


@app.post("/api/zones/{zone}/heatwave")
def heatwave(zone: str, req: ZoneEventRequest):
    if engine.sim is None or zone not in engine.sim.zones:
        raise HTTPException(404, f"Unknown zone {zone}")
    engine.zone_event(zone, magnitude_t=req.magnitude_t)
    return {"status": "ok", "zone": zone}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connected_sockets.append(websocket)
    try:
        await websocket.send_json(engine.snapshot())
        while True:
            await websocket.receive_text()  # keep the connection alive; input ignored
    except WebSocketDisconnect:
        if websocket in connected_sockets:
            connected_sockets.remove(websocket)


app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
def index():
    return FileResponse("static/index.html")
