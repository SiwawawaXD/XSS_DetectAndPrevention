# normalizer/utils/normalize.py
import re
import html
import urllib.parse
import base64

MAX_DECODE_ROUNDS = 5

def try_base64_decode(s):
    try:
        # ignore if too short or contains whitespace
        candidate = s.strip()
        if len(candidate) < 8:
            return None
        decoded = base64.b64decode(candidate, validate=True)
        # require the result to be mostly printable
        text = decoded.decode("utf-8", errors="ignore")
        if any(ch.isalpha() for ch in text):
            return text
    except Exception:
        return None
    return None

def normalize_payload(payload: str) -> str:
    """Canonicalize payload: multilayer decode -> strip noise -> collapse whitespace."""
    if not payload:
        return ""

    p = payload

    # 1) HTML unescape
    p = html.unescape(p)

    # 2) iterative decoding (url, html, base64, hex) but bounded
    for _ in range(MAX_DECODE_ROUNDS):
        prev = p
        try:
            p = urllib.parse.unquote(p)
        except Exception:
            pass

        # attempt base64 decode if it looks like base64
        b64 = try_base64_decode(p)
        if b64:
            p = b64

        # hex decode: if string is like %3c or 3c... naive approach
        try:
            # remove common separators then try hex decode
            hex_candidate = re.sub(r"[^0-9a-fA-F]", "", p)
            if len(hex_candidate) >= 4 and len(hex_candidate) % 2 == 0:
                decoded = bytes.fromhex(hex_candidate).decode("utf-8", errors="ignore")
                if decoded and any(ch.isalpha() for ch in decoded):
                    p = decoded
        except Exception:
            pass

        # html entities again
        p = html.unescape(p)

        if p == prev:
            break

    # 3) remove comments and control chars
    p = re.sub(r"/\*.*?\*/", "", p, flags=re.DOTALL)
    p = re.sub(r"[\x00-\x1f\x7f]+", " ", p)

    # 4) replace non-printable or dangerous separators with single space
    p = re.sub(r"[^\w\-\.:/=@&%#<>\"'()\[\]\{\};,]+", " ", p)

    # 5) collapse whitespace
    p = re.sub(r"\s+", " ", p).strip()

    # 6) lowercase for canonicalization
    p = p.lower()

    return p
