"""Untrusted text rendering; no wallet or network dependencies."""
_BIDI_CHARS = set("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

def safe_terminal_text(s, limit=None):
    """Escape terminal-unsafe characters for display. Never raises.

    Neutralizes C0/C1 control characters, ESC, bidi overrides, and embedded
    newlines — a malicious NFT URI, title, or description could otherwise
    redraw terminal output or inject a fake ceremony line (e.g. a fake
    price/seller). Printable Unicode (emoji, CJK, accented characters)
    passes through unchanged, so legitimate metadata stays readable.
    """
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif o < 0x20 or o == 0x7F:
            out.append(f"\\x{o:02x}")
        elif 0x80 <= o <= 0x9F:
            out.append(f"\\u{o:04x}")
        elif ch in _BIDI_CHARS:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    txt = "".join(out)
    if limit is not None and len(txt) > limit:
        txt = txt[:limit - 1] + "…"
    return txt
