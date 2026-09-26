#!/usr/bin/env python3
"""Read-only client for the XRPresso Discovery API v1.

Base: https://xrpresso.io/api/v1 — free, anonymous, no API key.
Contract: OpenAPI 3.0.3 at https://xrpresso.io/api/v1/openapi.json
(Discovery API v1.0.0; contract read 2026-09-25).

What this client enforces on top of the platform's own limits:
- polite client-side throttling: MIN_INTERVAL between calls (default 3s,
  ~20 calls/min, comfortably under the platform's 30/min IP limit)
- 15s timeout, 1MB response cap, strict JSON parsing
- deep-link validation: only https URLs on xrpresso.io (or a subdomain
  of it) are ever displayed; anything else is withheld, never printed
- the v1 API has no write endpoints and none are attempted here

This module never touches ~/.xrpl, never touches the ledger, never
signs anything. It needs no policy changes and no approval flow.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://xrpresso.io/api/v1"
TIMEOUT = 15  # seconds per request
MIN_INTERVAL = 3.0  # seconds between requests (~20/min < 30/min limit)
MAX_BYTES = 1_000_000  # 1MB response cap
MAX_URL_LEN = 2048
ALLOWED_HOST = "xrpresso.io"
USER_AGENT = "xrpl-muse-skill/xrpresso-discovery (read-only)"

_last_call_ts = 0.0


class XRPressoError(Exception):
    """Anything that stops an XRPresso discovery call."""


def _throttle():
    """Space requests out so we stay far under the 30/min IP limit."""
    global _last_call_ts
    now = time.monotonic()
    wait = MIN_INTERVAL - (now - _last_call_ts)
    if wait > 0:
        time.sleep(wait)
    _last_call_ts = time.monotonic()


def _read_capped(resp):
    chunks = []
    total = 0
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_BYTES:
            raise XRPressoError(
                f"XRPresso response exceeded {MAX_BYTES} bytes — refused")
        chunks.append(chunk)
    return b"".join(chunks)


def _get(path, params=None):
    """GET a v1 path. Returns the parsed JSON body. Raises XRPressoError."""
    if not path.startswith("/"):
        raise XRPressoError(f"bad API path {path!r}")
    url = BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    _throttle()
    req = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    try:
        resp = urllib.request.urlopen(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry = e.headers.get("Retry-After") if e.headers else None
            hint = f" — retry after {retry}s" if retry else ""
            raise XRPressoError(
                f"XRPresso rate limit hit (429){hint}; wait and retry")
        if e.code == 404:
            raise XRPressoError("not found or not public on XRPresso (404)")
        if e.code == 503:
            raise XRPressoError("XRPresso public API is disabled (503)")
        raise XRPressoError(f"XRPresso returned HTTP {e.code}")
    except urllib.error.URLError as e:
        raise XRPressoError(f"network error contacting XRPresso: {e.reason}")
    except (TimeoutError, OSError) as e:
        raise XRPressoError(f"XRPresso request failed: {e}")
    body = _read_capped(resp)
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise XRPressoError("XRPresso returned invalid JSON")


def _data_list(doc, what):
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, list):
        raise XRPressoError(f"unexpected XRPresso response shape for {what}")
    return data


def _data_obj(doc, what):
    data = doc.get("data") if isinstance(doc, dict) else None
    if not isinstance(data, dict):
        raise XRPressoError(f"unexpected XRPresso response shape for {what}")
    return data


# ---------- deep-link validation ----------

def sanitize_url(raw):
    """Return a displayable https URL, or None if untrusted.

    Only https URLs on xrpresso.io (or a subdomain of it) pass.
    Rejects: wrong scheme (http/javascript:/data:), off-host URLs,
    lookalike hosts (xrpresso.io.evil.com), userinfo smuggling,
    non-default ports, overlong URLs, whitespace/control characters.
    The returned URL keeps its query string (incl. ?ref=api_v1 for
    attribution) and drops any fragment.
    """
    if not isinstance(raw, str):
        return None
    raw = raw.strip()
    if not raw or len(raw) > MAX_URL_LEN:
        return None
    if any(ord(c) < 32 or c in " \t" for c in raw):
        return None
    try:
        p = urllib.parse.urlparse(raw)
    except ValueError:
        return None
    if p.scheme != "https":
        return None
    if p.username or p.password:
        return None
    host = (p.hostname or "").lower()
    if host != ALLOWED_HOST and not host.endswith("." + ALLOWED_HOST):
        return None
    try:
        port = p.port
    except ValueError:
        return None
    if port not in (None, 443):
        return None
    path = p.path or "/"
    url = urllib.parse.urlunparse(("https", host, path, "", p.query, ""))
    return url


def deep_link(raw):
    """Display form of a deep link: the URL, or a withheld notice."""
    url = sanitize_url(raw)
    if url:
        return url
    return "[link withheld — untrusted URL]"


# ---------- API calls ----------

def _check_limit(limit, default_max=50):
    if not isinstance(limit, int) or isinstance(limit, bool):
        raise XRPressoError("limit must be an integer")
    if not 1 <= limit <= default_max:
        raise XRPressoError(f"limit must be 1..{default_max}")
    return limit


def _check_sort(sort, allowed):
    if sort not in allowed:
        raise XRPressoError(f"sort must be one of {sorted(allowed)}")
    return sort


def get_stats():
    """Platform aggregates: active listings, NFTs, auctions, volume."""
    return _data_obj(_get("/stats"), "stats")


def get_categories():
    """Snake_case category keys usable as ?category= on /listings."""
    return _data_list(_get("/categories"), "categories")


def get_listings(category=None, q=None, limit=20, sort="newest",
                 currency=None, page=1):
    """Search active marketplace listings (goods, gigs, ...)."""
    _check_limit(limit)
    _check_sort(sort, {"newest", "price_asc", "price_desc", "ending_soon"})
    params = {"limit": limit, "sort": sort, "page": page}
    if category:
        params["category"] = str(category)
    if q is not None:
        q = str(q)
        if len(q) < 2:
            raise XRPressoError("search query needs at least 2 characters")
        params["q"] = q
    if currency is not None:
        if currency not in ("XRP", "RLUSD"):
            raise XRPressoError("currency must be XRP or RLUSD")
        params["currency"] = currency
    if not isinstance(page, int) or isinstance(page, bool) or page < 1:
        raise XRPressoError("page must be a positive integer")
    return _data_list(_get("/listings", params), "listings")


def get_listing(listing_id):
    """Full detail for one listing by id."""
    if not isinstance(listing_id, str) or not listing_id.strip():
        raise XRPressoError("listing id must be a non-empty string")
    seg = urllib.parse.quote(listing_id.strip(), safe="")
    return _data_obj(_get(f"/listings/{seg}"), "listing")


def get_nft_listings(q=None, limit=20, sort="newest"):
    """XRPresso-native listed NFTs."""
    _check_limit(limit)
    _check_sort(sort, {"newest", "price_asc", "price_desc"})
    params = {"limit": limit, "sort": sort}
    if q is not None:
        q = str(q)
        if len(q) < 2:
            raise XRPressoError("search query needs at least 2 characters")
        params["q"] = q
    return _data_list(_get("/nft/listings", params), "nft listings")


def get_nft_auctions(limit=12):
    """Live XRPresso-native NFT auctions."""
    _check_limit(limit)
    return _data_list(_get("/nft/auctions", {"limit": limit}), "nft auctions")


# ---------- display ----------

def _text(v):
    """Coerce an API string field to safe display text."""
    if v is None:
        return ""
    s = str(v)
    return s if len(s) <= 300 else s[:297] + "..."


def _price(item):
    price, ccy = item.get("price"), item.get("currency") or ""
    if isinstance(price, bool) or not isinstance(price, (int, float)):
        return "price not shown"
    ccy = str(ccy).upper()
    return f"{price:g} {ccy}".strip()


def fmt_listing(it, detail=False):
    lines = [f"[listing] {_text(it.get('title')) or '(no title)'}"]
    lines.append(f"  price: {_price(it)}")
    bits = []
    if it.get("category"):
        bits.append(f"category: {_text(it.get('category'))}")
    if it.get("deliveryMethod"):
        bits.append(f"delivery: {_text(it.get('deliveryMethod'))}")
    if it.get("escrowProtected") is True:
        bits.append("escrow-protected")
    if bits:
        lines.append("  " + " · ".join(bits))
    seller = it.get("seller") or {}
    if isinstance(seller, dict):
        who = _text(seller.get("displayName")) or ""
        if seller.get("xUsername"):
            who += f" (@{_text(seller.get('xUsername'))})"
        if who.strip():
            lines.append(f"  seller: {who.strip()}")
    if detail and it.get("description"):
        lines.append(f"  {_text(it.get('description'))}")
    lines.append(f"  view/buy: {deep_link(it.get('url'))}")
    return "\n".join(lines)


def fmt_nft(it):
    lines = [f"[nft] {_text(it.get('name')) or '(no name)'}"]
    if it.get("collectionName"):
        lines.append(f"  collection: {_text(it.get('collectionName'))}")
    lines.append(f"  price: {_price(it)}")
    if it.get("sellerAddress"):
        lines.append(f"  seller: {_text(it.get('sellerAddress'))}")
    lines.append(f"  view/buy: {deep_link(it.get('url'))}")
    return "\n".join(lines)


def fmt_auction(it):
    lines = [f"[auction] {_text(it.get('name')) or '(no name)'}"]
    if it.get("collectionName"):
        lines.append(f"  collection: {_text(it.get('collectionName'))}")
    lines.append(f"  current bid: {_price(it)}")
    if it.get("endsAt"):
        lines.append(f"  ends: {_text(it.get('endsAt'))}")
    if it.get("sellerAddress"):
        lines.append(f"  seller: {_text(it.get('sellerAddress'))}")
    lines.append(f"  view/bid: {deep_link(it.get('url'))}")
    return "\n".join(lines)


def fmt_stats(d):
    def num(k):
        v = d.get(k)
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) \
            else "?"

    return "\n".join([
        "XRPresso marketplace stats (live)",
        f"  active listings: {num('activeListings')}",
        f"  listed NFTs:     {num('listedNfts')}",
        f"  live auctions:   {num('liveAuctions')}",
        f"  live drops:      {num('liveDrops')}",
        f"  total volume:    {num('volumeXrpTotal')} XRP",
    ])


def fmt_categories(cats):
    lines = ["XRPresso listing categories (use with --category):"]
    for c in cats:
        if isinstance(c, dict) and c.get("key"):
            lines.append(f"  {_text(c['key'])}")
    return "\n".join(lines)
