#!/usr/bin/env python3
"""Farmers Union ($FARM) helper tests — no network.

Run: python3 tests/test_farm.py

Covers: references/farm.md exists and parses; `farm` is PUBLIC (in --help,
unlike hidden `fuzzy`); about/links output carries the issuer, the 123,000
threshold and all four links; qualify math (FARM balance above/below
threshold, LP valuation via fake amm_info, fail-open AMM, trustline audit
ready/missing); treasury aggregation with one wallet failing (fail-open);
dustings cache (fresh used as-is, stale triggers refetch, unparsable fetch
keeps old cache, no cache + failed fetch reports unavailable); the JS-table
parser; and the onboarding wizard (y adds `farmers-union`, n/Enter does not).
"""
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import time
from argparse import Namespace
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BIN = REPO / "bin"
FARM_MD = REPO / "references" / "farm.md"

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common")
T = load(BIN / "xrpl-trade", "xrpl_trade_farmtest")

# Point all ~/.xrpl file access at a temp dir (profile, dustings cache).
# NB: PROFILE_PATH is bound at import time, so rebind it too.
TMP = Path(tempfile.mkdtemp(prefix="xrpl-farm-test-"))
C.XRPL_DIR = TMP
C.PROFILE_PATH = TMP / "profile.json"

FARM_ISSUER = T.FARM_ISSUER
FARM_HEX = T.FARM_CURRENCY_HEX


def run_cli(*args):
    p = subprocess.run([sys.executable, str(BIN / "xrpl-trade"), *args],
                       capture_output=True, text=True, timeout=60)
    return p


# ---------- references/farm.md ----------
check("farm.md exists", FARM_MD.is_file())
farm_text = FARM_MD.read_text(encoding="utf-8") if FARM_MD.is_file() else ""
for needle in ["## About", "## Dev details", "## Links",
               "rPrAEfVATUNDTJm9CUa8tYeD7oJrVdEGhU", "123,000",
               "http://farmerunion.meme", "https://barn.farmerunion.meme",
               "xrpl.to/token/", "xrpl.to/nfts/animal-fam"]:
    check(f"farm.md contains {needle[:40]}", needle in farm_text)
check("farm.md links section parses",
      len(T._farm_ref_section("Links")) > 200)

# ---------- public command surface ----------
h = run_cli("--help")
check("--help exits 0", h.returncode == 0)
check("farm listed in --help (public, not hidden)",
      re.search(r"^\s*farm\b", h.stdout, re.MULTILINE) is not None)
fh = run_cli("farm", "--help")
check("farm --help exits 0", fh.returncode == 0)
for sub in ["about", "links", "qualify", "treasury", "dustings"]:
    check(f"farm --help lists {sub}", sub in fh.stdout)

r = run_cli("farm", "about")
check("farm about exits 0", r.returncode == 0)
check("about has issuer", FARM_ISSUER in r.stdout)
check("about has threshold", "123,000" in r.stdout)
check("about ends with shareable line", "Shareable:" in r.stdout)
check("about: no traceback",
      "Traceback" not in r.stdout and "Traceback" not in r.stderr)

r = run_cli("farm", "links")
check("farm links exits 0", r.returncode == 0)
for link in ["http://farmerunion.meme", "https://barn.farmerunion.meme",
             "https://xrpl.to/token/" + FARM_ISSUER + "-" + FARM_HEX,
             "https://xrpl.to/nfts/animal-fam"]:
    check(f"links has {link[:45]}", link in r.stdout)
check("links ends with shareable line", "Shareable:" in r.stdout)

# Missing reference file degrades gracefully (no network commands need it).
backup = FARM_MD.with_suffix(".md.bak")
FARM_MD.rename(backup)
try:
    r = run_cli("farm", "about")
    check("missing farm.md exits 0", r.returncode == 0)
    check("missing farm.md still prints shareable",
          "Shareable:" in r.stdout and FARM_ISSUER in r.stdout)
    check("missing farm.md: no traceback",
          "Traceback" not in r.stdout and "Traceback" not in r.stderr)
    r = run_cli("farm", "links")
    check("missing farm.md: links falls back to constants",
          "barn.farmerunion.meme" in r.stdout)
finally:
    backup.rename(FARM_MD)
check("farm.md restored", FARM_MD.is_file())


# ---------- fake XRPL client ----------
class FakeResp:
    def __init__(self, ok, result=None):
        self._ok = ok
        self.result = result or {}

    def is_successful(self):
        return self._ok


class FakeClient:
    """Routes client.request(req) by request type + account."""

    def __init__(self, routes):
        self.routes = routes

    def request(self, req):
        name = type(req).__name__
        acct = getattr(req, "account", None) or \
            getattr(req, "amm_account", None)
        key = (name, acct)
        if key not in self.routes:
            raise AssertionError(f"no fake route for {key}")
        out = self.routes[key]
        if isinstance(out, Exception):
            raise out
        return out


def lines_resp(*lines):
    return FakeResp(True, {"lines": list(lines)})


def farm_line(balance, currency="FARM"):
    return {"currency": currency, "account": FARM_ISSUER,
            "balance": str(balance), "limit": "999999999"}


LP_CUR = "03A5B8C9D0E1F203A5B8C9D0E1F203A5B8C9D0E1"
AMM_ACCT = "rAMM111111111111111111111111111"


def amm_resp(lp_outstanding, farm_in_pool):
    return FakeResp(True, {"amm": {
        "lp_token": {"currency": LP_CUR, "value": str(lp_outstanding)},
        "amount": {"currency": "FARM", "issuer": FARM_ISSUER,
                   "value": str(farm_in_pool)},
        "amount2": "5000000000",
    }})


def capture(fn, *args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        fn(*args)
    return buf.getvalue()


WALLET = "rWallet11111111111111111111111"


def qualify_out(lines, amm_routes=None, wallet=WALLET, wallet_arg="rW"):
    routes = {("AccountLines", wallet): lines_resp(*lines)}
    routes.update(amm_routes or {})
    args = Namespace(farm_cmd="qualify", wallet=wallet_arg)
    return capture(T.cmd_farm_qualify, args, {}, FakeClient(routes))


# ---------- qualify: threshold math ----------
out = qualify_out([farm_line(100000), farm_line(20000, FARM_HEX)],
                  wallet_arg=WALLET)
check("below threshold: NOT QUALIFIED", "NOT QUALIFIED" in out)
check("below threshold: exact gap shown", "3,000" in out)
check("below threshold: hex currency counted", "120,000" in out)

out = qualify_out([farm_line(130000)], wallet_arg=WALLET)
check("above threshold: QUALIFIED", "QUALIFIED" in out
      and "NOT QUALIFIED" not in out)

# ---------- qualify: LP valuation ----------
lp_line = {"currency": LP_CUR, "account": AMM_ACCT, "balance": "50",
           "limit": "999999999"}
# 50/200 of a pool holding 1,000,000 FARM = 250,000 FARM-equiv
out = qualify_out([farm_line(1000), lp_line],
                  {("AMMInfo", AMM_ACCT): amm_resp(200, 1000000)},
                  wallet_arg=WALLET)
check("LP equiv valued via amm_info", "251,000" in out)
check("LP equiv qualifies wallet", "QUALIFIED" in out
      and "NOT QUALIFIED" not in out)

# AMM failure is fail-open: note printed, no traceback, no invented value.
out = qualify_out([farm_line(1000), lp_line],
                  {("AMMInfo", AMM_ACCT): RuntimeError("boom")},
                  wallet_arg=WALLET)
check("amm failure: fail-open note", "amm_info unreachable" in out)
check("amm failure: LP equiv 0, still NOT QUALIFIED",
      "NOT QUALIFIED" in out)

# Pool with no FARM in it values to 0 with a note.
no_farm_amm = FakeResp(True, {"amm": {
    "lp_token": {"currency": LP_CUR, "value": "200"},
    "amount": "5000000000",
    "amount2": {"currency": "USD", "issuer": "rX", "value": "99"},
}})
out = qualify_out([lp_line], {("AMMInfo", AMM_ACCT): no_farm_amm},
                  wallet_arg=WALLET)
check("non-FARM pool: note shown", "no FARM in this pool" in out)

# ---------- qualify: trustline audit ----------
CACHE = TMP / "farm-dustings.json"
CACHE.write_text(json.dumps({
    "fetched_at": time.time(),
    "rows": [
        {"token": "$XRPLOL", "issuer": "rMDfsTapNvFSo7irSe6gYpPmYj3EjqbcqF",
         "status": "upcoming"},
        {"token": "$BURST", "issuer": "rLeGXSzGpGDxBnEPzCbYiUofRTcnHMnGif",
         "status": "upcoming"},
        {"token": "$REMO", "issuer": "r9qwksEcradcTQmU3Cz2mmmLVXUDfttNos",
         "status": "completed"},
    ],
}), encoding="utf-8")
ready_line = {"currency": "5852504C4F4C0000000000000000000000000000",
              "account": "rMDfsTapNvFSo7irSe6gYpPmYj3EjqbcqF",
              "balance": "0", "limit": "999999999"}
out = qualify_out([farm_line(200000), ready_line], wallet_arg=WALLET)
check("audit: READY for held issuer", "READY   $XRPLOL" in out)
check("audit: MISSING for absent issuer", "MISSING $BURST" in out)
check("audit: completed not listed as upcoming", "$REMO" not in out)
check("audit: safety caveat printed", "not an endorsement" in out)
check("qualify ends with shareable line", "Shareable:" in out)

# No cache -> helpful pointer, no crash.
CACHE.unlink()
out = qualify_out([farm_line(200000)], wallet_arg=WALLET)
check("no dustings cache: pointer printed",
      "farm dustings" in out and "Traceback" not in out)

# AccountLines down -> fail-open, no traceback.
routes = {("AccountLines", WALLET): RuntimeError("rpc down")}
out = capture(T.cmd_farm_qualify, Namespace(farm_cmd="qualify",
                                            wallet=WALLET),
              {}, FakeClient(routes))
check("AccountLines down: unavailable note",
      "AccountLines unavailable" in out)

# No wallet anywhere -> usage error, not a traceback.
out_buf = io.StringIO()
code = None
try:
    with redirect_stdout(out_buf):
        T.cmd_farm_qualify(Namespace(farm_cmd="qualify", wallet=None),
                           {}, FakeClient({}))
except SystemExit as e:
    code = e.code  # sys.exit("msg") -> code IS the message (goes to stderr)
check("no wallet: exits asking for one",
      code not in (0, None) and "No wallet" in str(code))

# ---------- treasury ----------
T1, T2, T3, T4 = [a for _, a in T.FARM_TREASURY_WALLETS]
treasury_routes = {
    ("AccountInfo", T1): FakeResp(True, {"account_data": {"Balance": "2000000"}}),
    ("AccountLines", T1): lines_resp(farm_line(50000)),
    ("AccountInfo", T2): FakeResp(True, {"account_data": {"Balance": "1000000"}}),
    ("AccountLines", T2): lines_resp(farm_line(25000)),
    ("AccountInfo", T3): RuntimeError("rpc down"),  # fail-open wallet
    ("AccountInfo", T4): FakeResp(True, {"account_data": {"Balance": "500000"}}),
    ("AccountLines", T4): lines_resp(),
}
out = capture(T.cmd_farm_treasury,
              Namespace(farm_cmd="treasury"), {}, FakeClient(treasury_routes))
check("treasury: failed wallet marked unavailable", "unavailable" in out)
check("treasury: XRP totals 3.5", "3.5" in out)  # 2+1+0.5 XRP
check("treasury: FARM totals 75,000", "75,000" in out)
check("treasury: 3/4 wallets counted", "3/4" in out)
check("treasury: published figure labeled as site figure",
      "site figure" in out and "148,150" in out)
check("treasury ends with shareable line", "Shareable:" in out)

# ---------- dustings cache behavior ----------
SAMPLE_ROWS = [
    {"token": "$XRPLOL", "issuer": "rMDfsTapNvFSo7irSe6gYpPmYj3EjqbcqF",
     "status": "upcoming",
     "trustline": "https://xrpl.services/?issuer=rMDfsTapNvFSo7irSe6gYpPmYj3EjqbcqF&currency=58&limit=1"},
    {"token": "$REMO", "issuer": "r9qwksEcradcTQmU3Cz2mmmLVXUDfttNos",
     "status": "completed"},
]


def write_cache(age_days):
    CACHE.write_text(json.dumps({
        "fetched_at": time.time() - age_days * 86400,
        "rows": [{"token": "$OLD", "issuer": "rOld11111111111111111111111",
                  "status": "completed"}],
    }), encoding="utf-8")


orig_fetch = T._farm_fetch_dustings

# Fresh cache: fetch must NOT be called.
write_cache(1)
T._farm_fetch_dustings = lambda: (_ for _ in ()).throw(
    AssertionError("fetch called on fresh cache"))
try:
    out = capture(T.cmd_farm_dustings,
                  Namespace(farm_cmd="dustings", refresh=False), {}, None)
finally:
    T._farm_fetch_dustings = orig_fetch
check("fresh cache used as-is (no fetch)", "$OLD" in out)
check("dustings prints data-as-of", "data as of" in out)
check("dustings ends with shareable line", "Shareable:" in out)

# Stale cache + good fetch -> refreshed and re-cached.
write_cache(8)
T._farm_fetch_dustings = lambda: [dict(r) for r in SAMPLE_ROWS]
try:
    out = capture(T.cmd_farm_dustings,
                  Namespace(farm_cmd="dustings", refresh=False), {}, None)
finally:
    T._farm_fetch_dustings = orig_fetch
check("stale cache triggers refresh", "refreshed from farmerunion.meme" in out)
check("refreshed board shows new rows", "$XRPLOL" in out)
saved = json.loads(CACHE.read_text(encoding="utf-8"))
check("refreshed board re-cached",
      any(r["token"] == "$XRPLOL" for r in saved["rows"]))

# Stale cache + unparsable fetch -> old cache kept, honest note.
write_cache(8)
T._farm_fetch_dustings = lambda: None
try:
    out = capture(T.cmd_farm_dustings,
                  Namespace(farm_cmd="dustings", refresh=False), {}, None)
finally:
    T._farm_fetch_dustings = orig_fetch
check("bad fetch keeps old cache", "$OLD" in out)
check("bad fetch says so", "showing cached board" in out)

# No cache + failed fetch -> unavailable, no traceback, no garbage written.
if CACHE.exists():
    CACHE.unlink()
T._farm_fetch_dustings = lambda: None
try:
    out = capture(T.cmd_farm_dustings,
                  Namespace(farm_cmd="dustings", refresh=False), {}, None)
finally:
    T._farm_fetch_dustings = orig_fetch
check("no cache + failed fetch: unavailable",
      "unavailable" in out and "Traceback" not in out)
check("no cache + failed fetch: nothing cached", not CACHE.exists())

# --refresh forces a fetch even on a fresh cache.
write_cache(1)
T._farm_fetch_dustings = lambda: [dict(r) for r in SAMPLE_ROWS]
try:
    out = capture(T.cmd_farm_dustings,
                  Namespace(farm_cmd="dustings", refresh=True), {}, None)
finally:
    T._farm_fetch_dustings = orig_fetch
check("--refresh forces refetch", "$XRPLOL" in out)

# ---------- JS table parser ----------
SAMPLE_JS = '''
var DUST=[{name:"$XRPLOL",issuerAddress:"rMDfsTapNvFSo7irSe6gYpPmYj3EjqbcqF",status:"Set Your Trustline"},
{name:"$REMO",issuerAddress:"r9qwksEcradcTQmU3Cz2mmmLVXUDfttNos",status:"Completed May 18, 2025"},
{name:"$BOOM",issuerAddress:"rf6ZcoQgwKFGNbvsFfu5PzouGvJSEZwg7t",status:"Ongoing"},
{name:"$A",issuerAddress:"rAAAAAAAAAAAAAAAAAAAAAAAAA",status:"Completed x"},
{name:"$B",issuerAddress:"rBBBBBBBBBBBBBBBBBBBBBBBBB",status:"Completed x"},
{name:"$C",issuerAddress:"rCCCCCCCCCCCCCCCCCCCCCCCCC",status:"Completed x"}];
var TL={$XRPLOL:"https://xrpl.services/?issuer=rMDfsTapNvFSo7irSe6gYpPmYj3EjqbcqF&currency=5852504C4F4C0000000000000000000000000000&limit=99999999999999"};
'''
rows = T._farm_parse_dustings_js(SAMPLE_JS)
check("parser: rows extracted", rows is not None and len(rows) == 6)
by_token = {r["token"]: r for r in rows} if rows else {}
check("parser: 'Set Your Trustline' -> upcoming",
      by_token.get("$XRPLOL", {}).get("status") == "upcoming")
check("parser: 'Completed …' -> completed",
      by_token.get("$REMO", {}).get("status") == "completed")
check("parser: 'Ongoing' -> upcoming",
      by_token.get("$BOOM", {}).get("status") == "upcoming")
check("parser: trustline link attached",
      by_token.get("$XRPLOL", {}).get("trustline", "").startswith(
          "https://xrpl.services/"))
check("parser: garbage JS -> None",
      T._farm_parse_dustings_js("no table here") is None)
check("parser: too few rows -> None",
      T._farm_parse_dustings_js(
          '{name:"$X",issuerAddress:"rAAAAAAAAAAAAAAAAAAAAAAAAA",'
          'status:"Completed x"}') is None)

# ---------- onboarding wizard ----------
def scripted(answers):
    it = iter(answers)
    def _in(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise AssertionError("ran out of scripted answers at: " + prompt)
    return _in


def run_wizard(farm_answer):
    prof = C.default_profile()
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.run_profile_init(prof, _input=scripted(
            ["", "", "", "", farm_answer, "", ""]), cfg=None, client=None)
    return prof, buf.getvalue()


prof, out = run_wizard("y")
check("wizard 'y' adds farmers-union interest",
      "farmers-union" in prof.get("interests", []))
check("wizard 'y' prints start-here pointer",
      "xrpl-trade farm about" in out)

prof, _ = run_wizard("n")
check("wizard 'n' does not add interest",
      "farmers-union" not in prof.get("interests", []))

prof, _ = run_wizard("")
check("wizard Enter (default no) does not add interest",
      "farmers-union" not in prof.get("interests", []))

fails = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} passed")
sys.exit(1 if fails else 0)
