#!/usr/bin/env python3
"""FUZZY deal scanner tests — no network. Run: python3 tests/test_fuzzy_deals.py

Covers: deal math (floor/median/threshold/ranking), per-collection stats,
cheapest ask wins per token, offer index captured for the nft-buy ceremony,
aggregator failure degrades to an "unavailable" note (no raise), --json
parses, arg validation, xrpl.to attribution present.
"""
import importlib.util
import io
import json
import sys
from contextlib import redirect_stdout
from decimal import Decimal
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


T = load(BIN / "xrpl-trade", "xrpl_trade_fuzzy_deals")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


# ---------- pure deal math ----------
f = T.fuzzy_find_deals

check("empty asks -> no market", f([], 20) == (None, None, []))

asks = [("a", Decimal("30"), "i1"), ("b", Decimal("20"), "i2"),
        ("c", Decimal("10"), "i3")]
floor, median, deals = f(asks, 20)
check("floor is min", floor == Decimal("10"))
check("median odd count", median == Decimal("20"))
check("10 is 50% below 20 -> deal", any(d[0] == "c" for d in deals))
check("20 is not below itself", not any(d[0] == "b" for d in deals))

asks4 = [("a", Decimal("40"), "i1"), ("b", Decimal("30"), "i2"),
         ("c", Decimal("20"), "i3"), ("d", Decimal("10"), "i4")]
floor4, median4, deals4 = f(asks4, 20)
check("median even count", median4 == Decimal("25"))
check("ranked best-first", [d[0] for d in deals4] == ["d", "c"])

fb, mb, db = f([("x", Decimal("96"), "i"), ("y", Decimal("64"), "i2")], 20)
check("median is 80", mb == Decimal("80"))
check("exactly 20% below flags", any(d[0] == "y" for d in db))
fb2, mb2, db2 = f([("x", Decimal("96"), "i"), ("y", Decimal("65"), "i2")], 20)
check("18.75% below does not flag", not any(d[0] == "y" for d in db2))

# ---------- trimmed median ----------
# 10 asks: 8 normal (~100), one dust (1), one whale (10000).
# plain median would be ~100; trimmed must ignore both extremes.
many = ([("dust", Decimal("1"), "i0")] +
        [(f"n{i}", Decimal("100"), f"i{i}") for i in range(1, 9)] +
        [("whale", Decimal("10000"), "i9")])
fl, med, dl = f(many, 20)
check("trimmed median ignores extremes", med == Decimal("100"))
check("dust is a deal vs trimmed median", any(d[0] == "dust" for d in dl))
check("whale is not a deal", not any(d[0] == "whale" for d in dl))
check("floor still true minimum", fl == Decimal("1"))

# small samples: trim backs off, plain median used
fl3, med3, _ = f([("a", Decimal("10"), "i1"), ("b", Decimal("20"), "i2"),
                  ("c", Decimal("30"), "i3")], 20)
check("tiny sample keeps plain median", med3 == Decimal("20"))
# explicit trim_fraction=0 disables trimming
_, med0, _ = f(many, 20, trim_fraction=0)
check("trim=0 gives untrimmed median", med0 == Decimal("100"))

# percentile rank: cheapest ask beats ~100%, priciest deal beats less
_, _, drank = f([("a", Decimal("10"), "i1"), ("b", Decimal("20"), "i2"),
                 ("c", Decimal("30"), "i3"), ("d", Decimal("40"), "i4")], 20)
ranks = {d[0]: d[4] for d in drank}
check("rank: cheapest beats most", ranks.get("a", 0) == 100.0)
check("rank: 20 is a deal beating 75%",
      abs(ranks.get("b", 0) - 75.0) < 0.01)

# ---------- cmd with fake xrpl.to ----------
class FakeXrplTo:
    def __init__(self, nfts_by_slug, offers_by_token, fail=False):
        self.nfts_by_slug = nfts_by_slug
        self.offers_by_token = offers_by_token
        self.fail = fail

    def api_get(self, path, params=None):
        if self.fail:
            raise RuntimeError("api down")
        if "/nft/collections/" in path and path.endswith("/nfts"):
            slug = path.split("/nft/collections/")[1].split("/nfts")[0]
            tids = self.nfts_by_slug.get(slug, [])
            return {"nfts": [{"NFTokenID": t} for t in tids]}
        if "/nft/offers/sell/" in path:
            tid = path.rsplit("/", 1)[1]
            return {"offers": self.offers_by_token.get(tid, [])}
        return None


def run_cmd(fake, **kw):
    args = type("A", (), {"threshold": 20, "limit": 10, "json": False, **kw})()
    real = T.xrpl_to
    T.xrpl_to = fake
    try:
        buf = io.StringIO()
        with redirect_stdout(buf):
            T.cmd_fuzzy_deals(args, {}, object())
        return buf.getvalue()
    finally:
        T.xrpl_to = real


def offer(drops, idx):
    return {"amount": str(drops), "nft_offer_index": idx}


fake = FakeXrplTo(
    {"fuzzybears": ["t1", "t2"], "fuzzy-bars": ["t3", "t4"]},
    {"t1": [offer(20_000_000, "oid1"), offer(30_000_000, "oid2")],
     "t2": [],
     "t3": [offer(5_000_000, "oid3")],
     "t4": [offer(20_000_000, "oid4")]})
out = run_cmd(fake)
check("cheapest ask wins per token", "oid2" not in out)
check("per-collection stats shown",
      "fuzzybears" in out and "fuzzy-bars" in out)
check("deep discount flagged as deal", "oid3" in out)
check("buy command carries offer index",
      "xrpl-trade nft-buy --offer-index oid3" in out)
check("xrpl.to attribution present", "xrpl.to" in out)
check("no 'worth' claims", "worth" not in out.lower())
check("cancel caveat present", "cancelled" in out)

out_json = run_cmd(fake, json=True)
parsed = json.loads(out_json)
check("--json parses", isinstance(parsed, dict))
check("--json carries collections", len(parsed["collections"]) == 2)
check("--json carries deals with index",
      any(d["offer_index"] == "oid3" for d in parsed["deals"]))

out_fail = run_cmd(FakeXrplTo({}, {}, fail=True))
check("aggregator failure -> unavailable note, no raise",
      "unavailable" in out_fail)

# USD equivalents shown when the price feed works
real_fetch = T.C.fetch_xrp_usd
T.C.fetch_xrp_usd = lambda timeout=10: 2.0
try:
    out_usd = run_cmd(fake)
finally:
    T.C.fetch_xrp_usd = real_fetch
check("USD equivalents shown", "~$40" in out_usd and "XRP $2.00" in out_usd)
check("XRP stays primary", "20 XRP (~$40)" in out_usd)

# price feed down -> XRP-only, no crash
T.C.fetch_xrp_usd = lambda timeout=10: None
try:
    out_no_usd = run_cmd(fake)
finally:
    T.C.fetch_xrp_usd = real_fetch
check("no price feed -> XRP-only, no crash",
      "~$" not in out_no_usd and "20 XRP" in out_no_usd)
real = T.xrpl_to
T.xrpl_to = None
try:
    buf = io.StringIO()
    a = type("A", (), {"threshold": 20, "limit": 10, "json": False})()
    with redirect_stdout(buf):
        T.cmd_fuzzy_deals(a, {}, object())
    check("missing module -> unavailable note", "unavailable" in buf.getvalue())
finally:
    T.xrpl_to = real

# ---------- arg validation ----------
for bad in (0, 91):
    a = type("A", (), {"threshold": bad, "limit": 10, "json": False})()
    try:
        T.cmd_fuzzy_deals(a, {}, object())
        check(f"threshold {bad} rejected", False)
    except SystemExit:
        check(f"threshold {bad} rejected", True)

a = type("A", (), {"threshold": 20, "limit": -1, "json": False})()
try:
    T.cmd_fuzzy_deals(a, {}, object())
    check("negative limit rejected", False)
except SystemExit:
    check("negative limit rejected", True)

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
