#!/usr/bin/env python3
"""Trusted-links registry tests — no network.

Run: python3 tests/test_trusted_links.py

Covers: the registry file exists, every URL in it is https, the FUZZY pilot
section carries its required entries, and no entry is a bare guess
(the capture queue / warning markers must stay honest).
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
LINKS = REPO / "references" / "trusted-links.md"

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


text = LINKS.read_text() if LINKS.exists() else ""
urls = re.findall(r"https?://[^\s)\"'<>]+", text)

check("registry file exists", LINKS.exists())
check("file is non-empty", len(text) > 500)
check("every URL is https", all(u.startswith("https://") for u in urls))
check("no URL has whitespace or obvious breakage",
      all(" " not in u and "\n" not in u for u in urls))

# FUZZY pilot — required entries
check("pilot: official site", "https://fuzzyxrp.com" in text)
check("pilot: official X", "https://x.com/fuzzy_xrp" in text)
check("pilot: issuer address", "rhCAT4hRdi2Y9puNdkpMzxrdKa5wkppR62" in text)
check("pilot: xrpl.to token page",
      "xrpl.to/token/rhCAT4hRdi2Y9puNdkpMzxrdKa5wkppR62" in text)
check("pilot: firstledger page", "firstledger.net/token-v2" in text)
check("pilot: xpmarket page", "xpmarket.com/dex/FUZZY" in text)
check("pilot: fuzzy-bars collection",
      "xrp.cafe/collection/fuzzy-bars" in text)
check("pilot: bearableguy123 non-endorsement note",
      "never endorsed" in text.lower())

# Honesty markers — unverified items must be flagged, never silent
check("unverified items flagged with warning marker", "⚠️" in text)
check("community resources labeled not-official",
      "NOT official" in text or "not official" in text.lower())
check("rules section present (verification policy)",
      "## Rules" in text)
check("hub sections started beyond the pilot",
      "## XRPL ecosystem" in text)

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
sys.exit(1 if failed else 0)
