"""
trust.py
--------
Per-device trust in [0, 1], with three interchangeable models so the
evaluation can compare them under the attack trust systems are known to
be weak to - an ON-OFF device that misbehaves briefly, then behaves long
enough to earn its trust back:

  ema    symmetric exponential moving average of (1 - anomaly score)
         (the original SentinelTwin model; regains trust as fast as it loses it)
  asym   asymmetric EMA: trust drops fast on bad behaviour and is rebuilt
         slowly, and every confirmed attack lowers the ceiling it can regain
  beta   beta reputation (Josang & Ismail 2002 style) with forgetting:
         trust = (good + 1) / (good + bad + 2)

Trust weights each device's vote in the zone consensus, so a low-trust
device cannot steer the reference it is judged against, and a repeat
offender reaches the diagnosis layer with a lower prior of honesty.
"""

from __future__ import annotations
from digital_twin import DeviceTwin, DeviceState

ATTACK_CAUSES = ("MALICIOUS_TAMPERING", "STEALTHY_TAMPERING", "DOS_FLOOD_ATTACK", "IDENTITY_SPOOFING")

EMA_ALPHA = 0.35
ASYM_DOWN, ASYM_UP = 0.5, 0.03
ASYM_CEILING_STEP = 0.15
BETA_FORGET = 0.995
ATTACK_PENALTY = 0.4


def _observation(twin: DeviceTwin) -> float:
    """1.0 = behaved this tick, 0.0 = clearly anomalous."""
    return max(0.0, min(1.0, 1.0 - twin.last_anomaly_score))


def note_confirmed_attack(twin: DeviceTwin, model: str) -> None:
    """Called once per incident when a security cause is confirmed."""
    st = twin.trust_state
    st["attacks"] = st.get("attacks", 0) + 1
    if model == "ema":
        twin.trust_score = max(0.0, twin.trust_score - ATTACK_PENALTY)
    elif model == "asym":
        st["ceiling"] = max(0.2, st.get("ceiling", 1.0) - ASYM_CEILING_STEP)
        twin.trust_score = max(0.0, twin.trust_score - ATTACK_PENALTY)
    elif model == "beta":
        st["bad"] = st.get("bad", 0.0) + 10.0
        good = st.setdefault("good", 20.0)
        twin.trust_score = (good + 1) / (good + st["bad"] + 2)


def update_trust(twin: DeviceTwin, model: str = "asym") -> None:
    if twin.state == DeviceState.ISOLATED:
        return  # no observations while cut off
    obs = _observation(twin)
    st = twin.trust_state
    if model == "ema":
        twin.trust_score = (1 - EMA_ALPHA) * twin.trust_score + EMA_ALPHA * obs
    elif model == "asym":
        ceiling = st.get("ceiling", 1.0)
        target = min(obs, ceiling)
        a = ASYM_DOWN if target < twin.trust_score else ASYM_UP
        twin.trust_score = (1 - a) * twin.trust_score + a * target
    elif model == "beta":
        good = st.get("good", 20.0) * BETA_FORGET + obs   # new devices start with modest prior credit
        bad = st.get("bad", 0.0) * BETA_FORGET + (1 - obs)
        st["good"], st["bad"] = good, bad
        twin.trust_score = (good + 1) / (good + bad + 2)
    else:
        raise ValueError(f"unknown trust model {model}")
    twin.trust_score = round(max(0.0, min(1.0, twin.trust_score)), 4)
