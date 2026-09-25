#!/usr/bin/env python3
"""XRPresso discovery unit/adversarial tests — no network.

Run: python3 tests/test_xrpresso.py

Covers: deep-link allow/deny matrix (scheme, host, lookalike hosts,
userinfo, ports, length, whitespace), response parsing for listings /
NFT listings / auctions / stats / categories, display formatting (never
prints an untrusted URL), HTTP error mapping (429 w/ and w/o
Retry-After, 404, 503, 500), malformed JSON, wrong response shape,
oversize payload refusal, network errors, argument validation (limit /
sort / currency / q / page / listing id), query-param encoding,
15s timeout + User-Agent on requests, and client-side throttling.
urllib is stubbed; nothing touches the network or ~/.xrpl.
"""
import importlib.util
import io
import json
import sys
import time
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


XP = load(BIN / "xrpl_xrpresso.py", "xrpl_xrpresso")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


# ---------- fake transport ----------

class FakeResp:
    def __init__(self, body: bytes, headers=None):
        self._body = body
        self.headers = dict(headers or {})
        self._pos = 0

    def read(self, n=65536):
        if n is None or n < 0:
            n = len(self._body) - self._pos
        chunk = self._body[self._pos:self._pos + n]
        self._pos += len(chunk)
        return chunk


calls = []   # (request, kwargs)
script = []  # ("resp", body, status, headers) | ("raise", exc)


def fake_urlopen(req, **kw):
    calls.append((req, kw))
    kind = script.pop(0)
    if kind[0] == "raise":
        raise kind[1]
    _, body, status, headers = kind
    if status != 200:
        raise urllib.error.HTTPError(
            req.full_url, status, "err", headers or {}, None)
    return FakeResp(body, headers)


real_urlopen = urllib.request.urlopen
urllib.request.urlopen = fake_urlopen


def given_json(obj, status=200, headers=None):
    script.append(("resp", json.dumps(obj).encode(), status, headers))


def reset():
    calls.clear()
    script.clear()
    XP._last_call_ts = 0.0


old_interval = XP.MIN_INTERVAL
XP.MIN_INTERVAL = 0  # tests control throttling explicitly


def expect_error(name, fn, needle):
    try:
        fn()
    except XP.XRPressoError as e:
        check(name, needle in str(e))
    except Exception as e:  # noqa: BLE001
        check(name + f" (wrong exc: {type(e).__name__})", False)
    else:
        check(name + " (no error raised)", False)


# ---------- deep-link validation ----------

check("https xrpresso.io link kept",
      XP.sanitize_url("https://xrpresso.io/listing/abc?ref=api_v1")
      == "https://xrpresso.io/listing/abc?ref=api_v1")
check("fragment dropped",
      XP.sanitize_url("https://xrpresso.io/listing/abc?ref=api_v1#top")
      == "https://xrpresso.io/listing/abc?ref=api_v1")
check("subdomain allowed",
      XP.sanitize_url("https://app.xrpresso.io/x") == "https://app.xrpresso.io/x")
check("host case-insensitive",
      XP.sanitize_url("https://XRPRESSO.IO/x") == "https://xrpresso.io/x")
check("explicit 443 allowed",
      XP.sanitize_url("https://xrpresso.io:443/x") == "https://xrpresso.io/x")
check("http denied", XP.sanitize_url("http://xrpresso.io/x") is None)
check("javascript: denied",
      XP.sanitize_url("javascript:alert(1)") is None)
check("data: denied",
      XP.sanitize_url("data:text/html,<script>") is None)
check("off-host denied",
      XP.sanitize_url("https://evil.com/x") is None)
check("lookalike host denied",
      XP.sanitize_url("https://xrpresso.io.evil.com/x") is None)
check("suffix trick denied",
      XP.sanitize_url("https://notxrpresso.io/x") is None)
check("userinfo smuggling denied",
      XP.sanitize_url("https://user@xrpresso.io/x") is None)
check("userinfo w/ password denied",
      XP.sanitize_url("https://u:p@xrpresso.io/x") is None)
check("non-default port denied",
      XP.sanitize_url("https://xrpresso.io:8443/x") is None)
check("bad port denied",
      XP.sanitize_url("https://xrpresso.io:abc/x") is None)
check("None denied", XP.sanitize_url(None) is None)
check("non-string denied", XP.sanitize_url(123) is None)
check("empty denied", XP.sanitize_url("  ") is None)
check("whitespace inside denied",
      XP.sanitize_url("https://xrpresso.io/a b") is None)
check("newline smuggling denied",
      XP.sanitize_url("https://xrpresso.io/x\nSet-Cookie: a") is None)
check("overlong denied",
      XP.sanitize_url("https://xrpresso.io/" + "a" * 3000) is None)
check("deep_link passes good url",
      XP.deep_link("https://xrpresso.io/nft/1?ref=api_v1")
      == "https://xrpresso.io/nft/1?ref=api_v1")
check("deep_link withholds evil url",
      XP.deep_link("https://evil.com/steal")
      == "[link withheld — untrusted URL]")

# ---------- parsing: listings ----------

reset()
given_json({"data": [
    {"id": "lst_1", "type": "listing", "title": "Neon print",
     "category": "art", "currency": "XRP", "price": 12.5,
     "deliveryMethod": "ship", "escrowProtected": True,
     "seller": {"displayName": "Lara", "xUsername": "lara_art"},
     "url": "https://xrpresso.io/listing/lst_1?ref=api_v1"},
    {"id": "lst_2", "type": "listing", "title": "Old gig",
     "currency": "RLUSD", "price": 3,
     "url": "https://evil.com/listing/lst_2"}],
    "meta": {"limit": 20}})
items = XP.get_listings()
check("listings parsed", len(items) == 2 and items[0]["id"] == "lst_1")
out = XP.fmt_listing(items[0])
check("listing shows title+price+seller",
      "Neon print" in out and "12.5 XRP" in out and "Lara" in out
      and "@lara_art" in out)
check("listing shows deep link",
      "https://xrpresso.io/listing/lst_1?ref=api_v1" in out)
out2 = XP.fmt_listing(items[1])
check("evil deep link never printed",
      "evil.com" not in out2 and "[link withheld" in out2)
check("escrow flag shown", "escrow-protected" in out)
req, kw = calls[0]
check("listings URL has defaults",
      req.full_url.startswith("https://xrpresso.io/api/v1/listings?")
      and "limit=20" in req.full_url and "sort=newest" in req.full_url)
check("timeout is 15s", kw.get("timeout") == 15)
check("user-agent set", "xrpresso" in req.get_header("User-agent").lower())

# ---------- parsing: detail ----------

reset()
given_json({"data": {"id": "lst_9", "type": "listing", "title": "Rare",
                     "description": "one of one",
                     "currency": "XRP", "price": 99,
                     "url": "https://xrpresso.io/listing/lst_9?ref=api_v1"},
            "meta": {}})
d = XP.get_listing("lst_9")
check("detail parsed", d["title"] == "Rare")
check("detail shows description",
      "one of one" in XP.fmt_listing(d, detail=True))
req, _ = calls[0]
check("detail path correct",
      req.full_url == "https://xrpresso.io/api/v1/listings/lst_9")

reset()
given_json({"data": {"id": "a b/c", "title": "t",
                     "url": "https://xrpresso.io/listing/x"},
            "meta": {}})
XP.get_listing("a b/c")
req, _ = calls[0]
check("listing id is URL-quoted",
      req.full_url == "https://xrpresso.io/api/v1/listings/a%20b%2Fc")

# ---------- parsing: nfts / auctions / stats / categories ----------

reset()
given_json({"data": [
    {"id": "n1", "type": "nft_listing", "name": "Drift #1",
     "collectionName": "Neon Drift", "price": 45, "currency": "XRP",
     "sellerAddress": "rABC", "url": "https://xrpresso.io/nft/n1?ref=api_v1"}],
    "meta": {}})
nfts = XP.get_nft_listings(q="drift", sort="price_asc")
check("nft listings parsed", len(nfts) == 1)
out = XP.fmt_nft(nfts[0])
check("nft shows name/collection/price/seller/link",
      all(s in out for s in
          ["Drift #1", "Neon Drift", "45 XRP", "rABC",
           "https://xrpresso.io/nft/n1?ref=api_v1"]))
req, _ = calls[0]
check("nft query encoded",
      "q=drift" in req.full_url and "sort=price_asc" in req.full_url)

reset()
given_json({"data": [
    {"id": "a1", "type": "nft_auction", "name": "Genesis",
     "price": 10, "currency": "XRP", "endsAt": "2026-10-01T00:00:00Z",
     "sellerAddress": "rDEF",
     "url": "https://xrpresso.io/auction/a1?ref=api_v1"}],
    "meta": {}})
aucs = XP.get_nft_auctions(limit=5)
check("auctions parsed", len(aucs) == 1)
out = XP.fmt_auction(aucs[0])
check("auction shows bid/ends/link",
      "10 XRP" in out and "2026-10-01T00:00:00Z" in out
      and "https://xrpresso.io/auction/a1?ref=api_v1" in out)

reset()
given_json({"data": {"activeListings": 1, "listedNfts": 36,
                     "liveAuctions": 0, "liveDrops": 1,
                     "volumeXrpTotal": 270.75},
            "meta": {}})
st = XP.get_stats()
out = XP.fmt_stats(st)
check("stats formatted",
      "active listings: 1" in out and "listed NFTs:     36" in out
      and "270.75 XRP" in out)

reset()
given_json({"data": [{"id": "c1", "type": "listing_category",
                      "key": "art",
                      "url": "https://xrpresso.io/api/v1/listings?category=art"},
                     {"id": "c2", "type": "listing_category",
                      "key": "music", "url": "x"}],
            "meta": {}})
cats = XP.get_categories()
check("categories parsed", [c["key"] for c in cats] == ["art", "music"])
check("categories formatted",
      "art" in XP.fmt_categories(cats) and "music" in XP.fmt_categories(cats))

# ---------- argument validation ----------

reset()
expect_error("limit 0 refused", lambda: XP.get_listings(limit=0), "1..50")
expect_error("limit 51 refused", lambda: XP.get_listings(limit=51), "1..50")
expect_error("limit str refused",
             lambda: XP.get_listings(limit="20"), "integer")
expect_error("limit bool refused",
             lambda: XP.get_listings(limit=True), "integer")
expect_error("bad sort refused",
             lambda: XP.get_listings(sort="hax"), "sort must be")
expect_error("nft bad sort refused",
             lambda: XP.get_nft_listings(sort="ending_soon"), "sort must be")
expect_error("bad currency refused",
             lambda: XP.get_listings(currency="BTC"), "XRP or RLUSD")
expect_error("short q refused",
             lambda: XP.get_listings(q="a"), "2 characters")
expect_error("page 0 refused",
             lambda: XP.get_listings(page=0), "positive integer")
expect_error("empty listing id refused",
             lambda: XP.get_listing("  "), "non-empty")
expect_error("non-string listing id refused",
             lambda: XP.get_listing(None), "non-empty")
expect_error("bad path refused",
             lambda: XP._get("nope"), "bad API path")
check("no HTTP calls made for refused args", not calls)

reset()
given_json({"data": [], "meta": {}})
XP.get_listings(q="a b&c=d", currency="RLUSD", category="art")
req, _ = calls[0]
check("query params encoded",
      "q=a+b%26c%3Dd" in req.full_url and "currency=RLUSD" in req.full_url
      and "category=art" in req.full_url)

# ---------- HTTP / transport errors ----------

reset()
script.append(("resp", b"", 429, {"Retry-After": "7"}))
expect_error("429 maps with retry hint",
             XP.get_stats, "429")
script.append(("resp", b"", 429, {"Retry-After": "7"}))
try:
    XP.get_stats()
    check("429 no-error path", False)
except XP.XRPressoError as e:
    check("429 mentions retry-after", "7" in str(e))
    check("429 says retryable", "retry" in str(e).lower())
reset()
script.append(("resp", b"", 429, {}))
expect_error("429 without header still clear",
             XP.get_stats, "rate limit")
reset()
script.append(("resp", b"", 404, {}))
expect_error("404 maps to not-found", XP.get_stats, "not found")
reset()
script.append(("resp", b"", 503, {}))
expect_error("503 maps to disabled", XP.get_stats, "disabled")
reset()
script.append(("resp", b"", 500, {}))
expect_error("500 maps to HTTP code", XP.get_stats, "HTTP 500")

reset()
script.append(("resp", b"<html>not json", 200, {}))
expect_error("malformed JSON refused", XP.get_stats, "invalid JSON")

reset()
script.append(("resp", b"\xff\xfe bad bytes", 200, {}))
expect_error("bad encoding refused", XP.get_stats, "invalid JSON")

reset()
given_json([1, 2, 3])
expect_error("non-dict body refused", XP.get_stats, "unexpected")
reset()
given_json({"data": {"not": "a list"}})
expect_error("data-not-list refused", XP.get_listings, "unexpected")
reset()
given_json({"data": ["not", "dicts"]})
expect_error("data-not-dict refused", lambda: XP.get_listing("x"), "unexpected")
reset()
given_json({"nope": 1})
expect_error("missing data refused", XP.get_stats, "unexpected")

reset()
script.append(("resp", b"x" * (XP.MAX_BYTES + 10), 200, {}))
expect_error("oversize payload refused", XP.get_stats, "exceeded")

reset()
script.append(("raise", urllib.error.URLError("dns broke")))
expect_error("URLError mapped", XP.get_stats, "network error")
reset()
script.append(("raise", TimeoutError("slow")))
expect_error("timeout mapped", XP.get_stats, "failed")

# ---------- throttling ----------

XP.MIN_INTERVAL = 0.2
reset()
given_json({"data": {}, "meta": {}})
given_json({"data": {}, "meta": {}})
t0 = time.monotonic()
XP.get_stats()
XP.get_stats()
elapsed = time.monotonic() - t0
check("throttle spaces calls", elapsed >= 0.2)
XP.MIN_INTERVAL = 0
reset()
given_json({"data": {}, "meta": {}})
given_json({"data": {}, "meta": {}})
t0 = time.monotonic()
XP.get_stats()
XP.get_stats()
check("zero interval means no sleep", time.monotonic() - t0 < 0.15)
XP.MIN_INTERVAL = old_interval

# ---------- display edge cases ----------

check("missing price shown as not-shown",
      "price not shown" in XP.fmt_nft({"name": "x",
                                       "url": "https://xrpresso.io/n/1"}))
check("bool price not shown",
      "price not shown" in XP.fmt_nft({"name": "x", "price": True,
                                       "url": "https://xrpresso.io/n/1"}))
check("int price formats",
      "12 XRP" in XP.fmt_listing({"title": "t", "price": 12,
                                  "currency": "XRP",
                                  "url": "https://xrpresso.io/l/1"}))
check("long text truncated",
      len(XP._text("y" * 400)) == 300 and XP._text("y" * 400).endswith("..."))
check("bool stats become ?",
      "?" in XP.fmt_stats({"activeListings": True, "listedNfts": 1,
                           "liveAuctions": 0, "liveDrops": 0,
                           "volumeXrpTotal": 0}))
check("missing title tolerated",
      "(no title)" in XP.fmt_listing({"url": "https://xrpresso.io/l/1"}))
check("missing name tolerated",
      "(no name)" in XP.fmt_nft({"url": "https://xrpresso.io/n/1"}))

# ---------- CLI wiring ----------

T = load(BIN / "xrpl-trade", "xrpl_trade_xp")
check("xrpl-trade exposes cmd_xrpresso", callable(getattr(T, "cmd_xrpresso", None)))

XP.get_stats = lambda: {"activeListings": 2, "listedNfts": 5,
                        "liveAuctions": 1, "liveDrops": 0,
                        "volumeXrpTotal": 10.0}
buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_xrpresso(SimpleNamespace(xp_cmd="stats"))
check("cmd_xrpresso stats prints",
      "active listings: 2" in buf.getvalue()
      and "read-only" in buf.getvalue())


def boom():
    raise XP.XRPressoError("kaput")


XP.get_stats = boom
try:
    with redirect_stdout(io.StringIO()):
        T.cmd_xrpresso(SimpleNamespace(xp_cmd="stats"))
    check("cmd_xrpresso error exits", False)
except SystemExit as e:
    check("cmd_xrpresso error exits",
          e.code == "XRPresso error: kaput")

urllib.request.urlopen = real_urlopen

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} xrpresso checks passed")
sys.exit(1 if n_fail else 0)
