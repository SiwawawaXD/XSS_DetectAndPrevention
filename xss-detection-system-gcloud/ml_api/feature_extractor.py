# feature_extractor.py
import re
import math

class FeatureExtractor:
    """
    Extract XSS features for ML model inference.
    The feature list must stay stable and match training.
    """

    FEATURE_ORDER = [
        "length",
        "num_special_chars",
        "num_digits",
        "num_spaces",
        "has_script",
        "has_javascript",
        "has_onerror",
        "has_onload",
        "has_onclick",
        "has_onfocus",
        "has_onmouseover",
        "has_alert",
        "has_eval",
        "has_document_cookie",
        "has_document_write",
        "has_window_location",
        "has_iframe",
        "has_embed",
        "has_object",
        "has_svg",
        "has_img",
        "has_base64",
        "has_data_uri",
        "has_hex_encoding",
        "has_unicode",
        "has_url_encoding",
        "has_html_entity",
        "entropy",
        "uppercase_ratio",
        "digit_ratio",
        "special_char_ratio",
        "dangerous_func_count",
        "html_tag_count"
    ]

    def calculate_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        probs = [float(text.count(c)) / len(text) for c in set(text)]
        return -sum(p * math.log2(p) for p in probs if p > 0)

    def extract(self, payload: str):
        if payload is None:
            payload = ""

        try:
            decoded = requests.utils.unquote(payload)
        except Exception:
            decoded = payload

        decoded_lower = decoded.lower()

        feats = {
            "length": len(payload),
            "num_special_chars": len(re.findall(r"[<>'\"()\{\}\[\]]", payload)),
            "num_digits": len(re.findall(r"\d", payload)),
            "num_spaces": payload.count(" "),

            # XSS indicators
            "has_script": int("<script" in decoded_lower),
            "has_javascript": int("javascript:" in decoded_lower),
            "has_onerror": int("onerror=" in decoded_lower),
            "has_onload": int("onload=" in decoded_lower),
            "has_onclick": int("onclick=" in decoded_lower),
            "has_onfocus": int("onfocus=" in decoded_lower),
            "has_onmouseover": int("onmouseover=" in decoded_lower),
            "has_alert": int("alert(" in decoded_lower),
            "has_eval": int("eval(" in decoded_lower),
            "has_document_cookie": int("document.cookie" in decoded_lower),
            "has_document_write": int("document.write" in decoded_lower),
            "has_window_location": int("window.location" in decoded_lower),
            "has_iframe": int("<iframe" in decoded_lower),
            "has_embed": int("<embed" in decoded_lower),
            "has_object": int("<object" in decoded_lower),
            "has_svg": int("<svg" in decoded_lower),
            "has_img": int("<img" in decoded_lower),
            "has_base64": int("base64" in decoded_lower),
            "has_data_uri": int("data:" in decoded_lower),

            # Encodings
            "has_hex_encoding": int(bool(re.search(r"\\x[0-9a-fA-F]{2}", payload))),
            "has_unicode": int(bool(re.search(r"\\u[0-9a-fA-F]{4}", payload))),
            "has_url_encoding": int(bool(re.search(r"%[0-9A-Fa-f]{2}", payload))),
            "has_html_entity": int(bool(re.search(r"&#\d+;", payload))),

            # Stats
            "entropy": self.calculate_entropy(payload),
            "uppercase_ratio": sum(1 for c in payload if c.isupper()) / max(len(payload), 1),
            "digit_ratio": len(re.findall(r"\d", payload)) / max(len(payload), 1),
            "special_char_ratio": len(re.findall(r"[<>'\"()\{\}\[\]]", payload)) / max(len(payload), 1),

            # More indicators
            "dangerous_func_count": sum(decoded_lower.count(f) for f in ["eval", "alert", "prompt", "confirm"]),
            "html_tag_count": len(re.findall(r"<[^>]+>", decoded_lower)),
        }

        # Ensure all keys exist
        for k in self.FEATURE_ORDER:
            feats.setdefault(k, 0.0)

        return feats

    def vectorize(self, features: dict):
        """Return features in fixed FEATURE_ORDER as a list."""
        return [float(features[k]) for k in self.FEATURE_ORDER]
