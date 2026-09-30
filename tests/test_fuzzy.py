#!/usr/bin/env python3
"""Fuzzy Easter egg tests — no network, no wallet.

Run: python3 tests/test_fuzzy.py

Covers: `fuzzy` is hidden from --help and every help listing, the dossier
prints the on-chain canon, the wisdom quote is always a genuine JoelKatz
quote from the lore file (never invented), the quote varies across runs,
and a missing lore file degrades gracefully instead of tracebacks.
"""
import os
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "bin" / "xrpl-trade"
LORE = REPO / "references" / "fuzzy-lore.md"

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def run(*args):
    p = subprocess.run([sys.executable, str(BIN), *args],
                       capture_output=True, text=True, timeout=60)
    return p


# ---------- lore file exists and carries the canon ----------
check("lore file exists", LORE.is_file())
lore = LORE.read_text(encoding="utf-8") if LORE.is_file() else ""
for needle in ["rhCAT4hRdi2Y9puNdkpMzxrdKa5wkppR62",
               "rHzWtXTBrArrGoLDixQAgcSD2dBisM19fF",
               "103971664", "103994743", "320,930,450,547",
               "96,667,279.75577", "bagpipes"]:
    check(f"canon mentions {needle[:18]}", needle in lore)

quotes = re.findall(r'"([^"]+)"',
                    re.search(r"## Fuzzy wisdom.*?(?=^## )", lore,
                              re.DOTALL | re.MULTILINE).group(0), re.DOTALL)
quotes = {" ".join(q.split()) for q in quotes}
check("wisdom pool has 5 genuine quotes", len(quotes) == 5)
check("no invented wisdom ('moon' check)",
      not any("moon" in q.lower() and "lambo" in q.lower() for q in quotes))

# ---------- hidden from help ----------
h = run("--help")
check("--help exits 0", h.returncode == 0)
check("fuzzy absent from --help", "fuzzy" not in h.stdout.lower())
check("fuzzy absent from --help stderr", "fuzzy" not in h.stderr.lower())

# ---------- the command works ----------
r = run("fuzzy")
check("fuzzy exits 0", r.returncode == 0)
check("dossier header printed", "THE FUZZY DOSSIER" in r.stdout)
check("JoelKatz mode footer printed", "JoelKatz mode engaged" in r.stdout)
check("not-in-the-menus wink printed", "not in the menus" in r.stdout)
check("no traceback", "Traceback" not in r.stdout and "Traceback" not in r.stderr)
m = re.search(r'FUZZY WISDOM OF THE MOMENT\n=+\n\s+"([^"]+)"', r.stdout)
shown = " ".join(m.group(1).split()) if m else ""
check("wisdom quote shown is from the genuine pool", shown in quotes)

# ---------- quote varies across runs ----------
seen = {shown}
for _ in range(9):
    rr = run("fuzzy")
    mm = re.search(r'FUZZY WISDOM OF THE MOMENT\n=+\n\s+"([^"]+)"', rr.stdout)
    if mm:
        seen.add(" ".join(mm.group(1).split()))
check("wisdom varies across runs", len(seen) >= 2)

# ---------- missing lore file degrades gracefully ----------
backup = LORE.with_suffix(".md.bak")
os.rename(LORE, backup)
try:
    r2 = run("fuzzy")
    check("missing lore exits 0", r2.returncode == 0)
    check("missing lore prints a graceful line",
          "bear has left the building" in r2.stdout)
    check("missing lore: no traceback",
          "Traceback" not in r2.stdout and "Traceback" not in r2.stderr)
finally:
    os.rename(backup, LORE)
check("lore file restored", LORE.is_file())

# ---------- SKILL.md and menus stay clean ----------
# (SKILL.md legitimately mentions the FUZZY token in examples; what must
# stay out is the easter egg itself: the command, the lore, JoelKatz mode.)
skill = (REPO / "SKILL.md").read_text(encoding="utf-8")
for needle in ["fuzzy lore", "joelkatz mode", "fuzzy wisdom", "fuzzy dossier",
               "xrpl-trade fuzzy", "`fuzzy`"]:
    check(f"SKILL.md has no easter-egg mention: {needle!r}",
          needle not in skill.lower())

fails = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} passed")
sys.exit(1 if fails else 0)
