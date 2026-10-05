#!/usr/bin/env python3
"""NFT Radar tests — no network. Run: python3 tests/test_nft_radar.py

Covers: arg validation (--days range, --limit), signal-only reporting
(artists without mints are silent), JSON output shape, empty directory
handling, newest-first ordering.
"""
import importlib.util
import io
import json
import sys
import tempfile
import time
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


T = load(BIN / "xrpl-trade", "xrpl_trade_nft_radar")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def make_args(**kw):
    d = {"days": 3, "limit": 20, "json": False}
    d.update(kw)
    return SimpleNamespace(**d)


ARTISTS = [
    {"name": "Alpha", "address": "rAlpha11111111111111111111111111",
     "cafe": "https://xrp.cafe/profile/rAlpha11111111111111111111111111"},
    {"name": "Beta", "address": "rBeta2222222222222222222222222222", "cafe": None},
    {"name": "Gamma", "address": "rGamma333333333333333333333333333", "cafe": None},
]

MINTS = {
    "rAlpha11111111111111111111111111": [
        {"date_unix": 1700000000, "token_ids": ["TOKEN_A1"],
         "ledger_index": 100, "uri_hex": "", "taxon": 0},
        {"date_unix": 1699900000, "token_ids": ["TOKEN_A2"],
         "ledger_index": 99, "uri_hex": "", "taxon": 0},
    ],
    "rBeta2222222222222222222222222222": [],
    "rGamma333333333333333333333333333": [
        {"date_unix": 1700100000, "token_ids": ["TOKEN_G1"],
         "ledger_index": 101, "uri_hex": "", "taxon": 0},
    ],
}


def run_radar(artists, args):
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "artist-directory.json"
        p.write_text(json.dumps(artists))
        with mock.patch.object(T, "_artist_directory_path", return_value=p), \
             mock.patch.object(T.C, "get_validated_ledger",
                               return_value=(999999, None)), \
             mock.patch.object(T.C, "scan_artist_mints",
                               side_effect=lambda client, addr, **kw: (
                                   MINTS.get(addr, []), 1, None)):
            buf = io.StringIO()
            with redirect_stdout(buf):
                T.cmd_nft_radar(args, {}, object())
            return buf.getvalue()


# ---------- arg validation ----------
for bad_days in (0, 31, -1):
    try:
        run_radar(ARTISTS, make_args(days=bad_days))
        check(f"--days={bad_days} rejected", False)
    except SystemExit as e:
        check(f"--days={bad_days} rejected", "must be between" in str(e))

try:
    run_radar(ARTISTS, make_args(limit=-1))
    check("--limit=-1 rejected", False)
except SystemExit as e:
    check("--limit=-1 rejected", "must be 0" in str(e))

# ---------- signal-only behavior ----------
out = run_radar(ARTISTS, make_args())
check("artists with mints reported", "Alpha" in out and "Gamma" in out)
check("artist without mints silent", "Beta" not in out)
check("mint count shown", "2 mint(s)" in out)
check("newest-first ordering", out.find("Gamma") < out.find("Alpha"))
check("summary line", "2 of 3 artists minted" in out)
check("cafe link shown", "xrp.cafe/profile/rAlpha" in out)

# ---------- empty result ----------
try:
    out = run_radar([], make_args())
    check("empty directory handled", "empty" in out.lower())
except SystemExit as e:
    check("empty directory handled", "empty" in str(e).lower())

# ---------- JSON output ----------
out = run_radar(ARTISTS, make_args(json=True))
data = json.loads(out)
check("json parses", isinstance(data, dict))
check("json has days", data.get("days") == 3)
check("json artists_scanned", data.get("artists_scanned") == 3)
check("json artists_with_mints", data.get("artists_with_mints") == 2)
check("json hits newest-first",
      data["hits"][0]["name"] == "Gamma" and data["hits"][1]["name"] == "Alpha")
check("json hit fields",
      all(k in data["hits"][0] for k in
          ("name", "address", "mint_count", "newest_utc", "token_ids")))

# ---------- limit ----------
out = run_radar(ARTISTS, make_args(limit=1))
check("limit caps output", "Gamma" in out and "Alpha" not in out)
check("limit notice", "raise with --limit" in out)

failed = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(failed)}/{len(PASS)} passed")
sys.exit(1 if failed else 0)
