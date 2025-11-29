# feature_extractor.py
# PURE feature extraction → used by trainer + ml_api

import re
import urllib.parse
import pandas as pd

class FeatureExtractor:

    def normalize(self, payload):
        try:
            payload = urllib.parse.unquote_plus(payload)
        except:
            pass
        return payload.lower().strip()

    def extract_features(self, payload):
        payload = self.normalize(payload)

        feats = {
            "len": len(payload),
            "count_lt": payload.count("<"),
            "count_gt": payload.count(">"),
            "count_script": len(re.findall(r"script", payload, flags=re.I)),
            "count_encoded": len(re.findall(r"%[0-9A-Fa-f]{2}", payload)),
            "count_entity": len(re.findall(r"&[#a-zA-Z0-9]+;", payload)),
            "has_javascript": int("javascript:" in payload),
            "has_onerror": int("onerror" in payload),
            "has_onload": int("onload" in payload),
            "has_alert": int("alert(" in payload),
            "has_iframe": int("<iframe" in payload),
            "has_svg": int("<svg" in payload),
            "contains_data_uri": int("data:" in payload),
        }

        return feats

    def extract_batch(self, payloads):
        return pd.DataFrame([self.extract_features(p) for p in payloads])
