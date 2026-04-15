from __future__ import annotations

from typing import Any

import pandas as pd


class FeatureTranslator:
    """Translate runtime signal fields into the exact model feature frame."""

    def __init__(self, tfidf: Any, svd: Any, features_list: list[str]):
        self.tfidf = tfidf
        self.svd = svd
        self.features_list = features_list

    def build_model_frame(self, base_features: dict[str, float], log_type: str, message: str) -> pd.DataFrame:
        """
        Return a single-row DataFrame with columns ordered exactly like features_list.

        This ensures both order and feature names match training-time expectations.
        """
        text_payload = f"{log_type} {message}".lower()
        x_tfidf = self.tfidf.transform([text_payload])
        x_svd = self.svd.transform(x_tfidf)[0]

        all_features = dict(base_features)
        for i in range(5):
            all_features[f"NLP_Dim_{i + 1}"] = float(x_svd[i])

        row = {name: float(all_features.get(name, 0.0)) for name in self.features_list}
        return pd.DataFrame([row], columns=self.features_list)
