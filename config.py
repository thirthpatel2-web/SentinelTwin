"""
config.py
---------
Every switch the evaluation ablates, in one place. The live server uses
the defaults (the full SentinelTwin pipeline); experiments flip one
switch at a time so each component's contribution is measured, not
asserted.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict


@dataclass
class PipelineConfig:
    # detection
    use_consensus: bool = True          # zone-consensus residuals (False = per-device baselines only)
    use_frozen_baseline: bool = True    # frozen calibration baseline (False = rolling window only)
    # security layer
    security_layer: bool = True         # False = one-stage design: everything goes straight to diagnosis
    rate_detector: str = "multiple"     # "multiple" (learned cadence x5) | "mu3sigma" (Rodrigues et al. 2025)
    use_provenance: bool = True         # sequence / publisher / MAC evidence
    use_auth: bool = False              # per-device message authentication on the wire
    scoped_quarantine: bool = True      # block only a rogue publisher when it is distinguishable
    permanent_block: bool = False       # baseline: never unblock
    # diagnosis
    use_comovement: bool = True         # does the device still track the zone's physics?
    comove_threshold: float = 0.2       # chosen on development seeds 1000-1019 (experiments/tune.py, results/tuning.json)
    comove_weight: float = 1.5
    use_rate_prior: bool = True         # physical bound on how fast real sensors drift
    max_plausible_drift: float = 0.4    # residual sigma per tick (time-compressed aging bound)
    # response
    policy: str = "expected_cost"       # expected_cost | argmax | naive_restart | no_heal
    verify: bool = True                 # closed-loop post-action verification
    # trust
    trust_model: str = "asym"           # ema | asym | beta
    trust_weighted_consensus: bool = True

    def as_dict(self) -> dict:
        return asdict(self)


DEFAULT = PipelineConfig()
