"""
ml/explainer.py — SHAP/LIME Explanation Generator (Phase 3 stub)
Full implementation in Phase 3.
"""

import logging

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """Generates SHAP-style feature importance explanations. Full impl: Phase 3."""

    def explain(self, features: dict) -> dict:
        logger.info("SHAPExplainer.explain called (Phase 3 stub)")
        return {"method": "shap", "features": [], "base_value": 0.0, "prediction": 0.0}


class LIMEExplainer:
    """Generates LIME-style local explanations. Full impl: Phase 3."""

    def explain(self, features: dict) -> dict:
        logger.info("LIMEExplainer.explain called (Phase 3 stub)")
        return {"method": "lime", "features": [], "prediction_proba": [1.0, 0.0], "intercept": 0.0}
