"""
clock.py
--------
A single swappable time source for the whole pipeline.

The live server runs on wall-clock time. Experiments swap in a SimClock
so that thousands of ticks run in seconds, every timestamp (detection,
diagnosis, containment, verified recovery) is exact, and a run with the
same seed is bit-for-bit reproducible. Every module that needs "now"
calls clock.now() instead of time.time().
"""

from __future__ import annotations
import time


class RealClock:
    def now(self) -> float:
        return time.time()


class SimClock:
    def __init__(self, start: float = 0.0) -> None:
        self._t = start

    def now(self) -> float:
        return self._t

    def advance(self, dt: float) -> None:
        self._t += dt


_current = RealClock()


def now() -> float:
    return _current.now()


def use(clock) -> None:
    """Swap the global time source (RealClock for the server, SimClock for experiments)."""
    global _current
    _current = clock


def current():
    return _current
