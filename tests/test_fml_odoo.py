#!/usr/bin/env python3
"""FML / Odoo-XRPL knowledge doc tests — no network.

Run: python3 tests/test_fml_odoo.py

Covers: the reference file exists, carries the required FML facts
(products, services, bridge description, caveats), and links back to the
trusted-links registry instead of inventing URLs.
"""
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "references" / "fml-odoo-xrpl.md"

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


text = DOC.read_text() if DOC.exists() else ""
low = text.lower()
urls = re.findall(r"https?://[^\s)\"'<>]+", text)

check("knowledge doc exists", DOC.exists())
check("doc is non-empty", len(text) > 1500)

# Odoo primer present
check("odoo primer: open-source ERP", "open-source erp" in low)
check("odoo primer: modular apps", "modular" in low)
check("odoo primer: FML site runs on Odoo", "xrpfml.odoo.com" in text)

# FML products (site's own terms)
check("product: Odoo-XRPL Bridge", "odoo-xrpl bridge" in low)
check("product: Sovereign Cloud Hosting", "sovereign cloud" in low)
check("product: Raven 5 Escrow", "raven 5" in low)

# FML services
check("service: Reg D / RWA advisory", "reg d" in low and "rwa" in low)
check("service: capital intro", "capital intro" in low)
check("service: business formation", "business formation" in low)
check("service: onboarding", "onboarding" in low)

# Honesty guardrails
check("caveat: no invented bridge capabilities",
      "do not invent" in low or "never add capabilities" in low)
check("caveat: HTTP-only custom domain flagged", "http-only" in low)
check("caveat: broken nav noted", "404" in text)
check("points to trusted-links registry", "trusted-links.md" in text)
check("every URL is https", all(u.startswith("https://") for u in urls))

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
sys.exit(1 if failed else 0)
