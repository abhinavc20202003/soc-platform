"""Learns what 'normal' looks like from baseline events."""
import numpy as np
from sklearn.ensemble import IsolationForest

import config
from ml_engine.baseline import generate_baseline_events
from ml_engine.features import FEATURES, build_windows, normalize_user, to_matrix


class Baseline:
    """Holds everything learned from normal activity:
    an Isolation Forest, per-feature mean/std, and a user -> known-IPs profile."""

    def __init__(self, events=None):
        events = generate_baseline_events() if events is None else events
        rows = build_windows(events, config.ML_WINDOW_MINUTES)
        if len(rows) < 20:
            raise ValueError("Baseline needs at least 20 activity windows")
        X = np.array(to_matrix(rows), dtype=float)

        self.forest = IsolationForest(
            n_estimators=200,
            contamination=config.ML_CONTAMINATION,
            random_state=config.ML_RANDOM_SEED,
        ).fit(X)

        self.mean = dict(zip(FEATURES, X.mean(axis=0)))
        # Floor of 1.0 stops tiny baseline variance from making z-scores explode.
        self.std = dict(zip(FEATURES, np.maximum(X.std(axis=0), 1.0)))

        self.profile = {}
        for e in events:
            if e["event_type"] == "login_success" and e.get("username") and e.get("source_ip"):
                self.profile.setdefault(normalize_user(e["username"]), set()).add(e["source_ip"])