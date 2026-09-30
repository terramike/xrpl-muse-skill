"""xrpl_eco — keyless read-only XRP Ledger ecosystem connectors (Tier 1).

Covers: signed validator lists, amendments status (public rippled RPC),
XRPL Meta token metadata (second risk opinion), OnTheDEX price data.

Every public function is advisory + fail-open: network/API failures
return "unavailable" lines, never raise, never block. Provenance is
labeled on every line. Nothing here is authoritative over the validated
ledger.

Spec: references/ecosystem-connectors.md
"""

import base64
import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

UA = "xrpl-muse-skill/1.0"
RIPPLE_EPOCH = 946684800  # seconds between 1970-01-01 and 2000-01-01

VL_SOURCES = [
    ("xrplf", "https://unl.xrplf.org"),
    ("ripple", "https://vl.ripple.com"),
]

RPC_SERVERS = [
    "https://s1.ripple.com:51234",
    "https://xrplcluster.com",
]

XRPLMETA_BASE = "https://s1.xrplmeta.org"
ONTHEDEX_BASE = "https://api.onthedex.live/public/v1"

XRPSCAN_BASE = "https://api.xrpscan.com/api/v1"
XRPSCAN_NOTE = "(per api.xrpscan.com — CC BY-NC-SA 4.0, non-commercial)"

DEFILLAMA_STABLE = "https://stablecoins.llama.fi"
DEXSCREENER_BASE = "https://api.dexscreener.com"

SEEN_PATH = Path.home() / ".xrpl" / "hidden_files" / "validators-seen.json"


def _fmt_usd(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return "n/a"
    if f >= 1e9:
        return f"${f/1e9:.2f}B"
    if f >= 1e6:
        return f"${f/1e6:.2f}M"
    if f >= 1e3:
        return f"${f/1e3:.1f}K"
    return f"${f:.2f}"


# ---------------------------------------------------------------- HTTP

def _headers():
    return {"User-Agent": UA, "Accept": "application/json"}


def _http_get_json(url, timeout=20, retries=3):
    """GET JSON. Returns parsed object. Raises on failure."""
    last = None
    for i in range(retries):
        try:
            req = urllib.request.Request(url, headers=_headers())
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001 — retried, then raised
            last = e
            time.sleep(1 + i)
    raise last


def _http_post_json(url, payload, timeout=25, retries=3):
    """POST JSON body, parse JSON response. Raises on failure."""
    last = None
    for i in range(retries):
        try:
            body = json.dumps(payload).encode()
            req = urllib.request.Request(
                url, data=body,
                headers={**_headers(), "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", "replace"))
        except Exception as e:  # noqa: BLE001 — retried, then raised
            last = e
            time.sleep(1 + i)
    raise last


def currency_to_hex(ccy):
    """3-char ASCII codes pass through; longer names -> 160-bit hex."""
    ccy = (ccy or "").strip()
    if len(ccy) == 3 and all(32 < ord(c) < 127 for c in ccy):
        return ccy
    raw = ccy.encode("utf-8")[:20].ljust(20, b"\x00")
    return raw.hex().upper()


# ---------------------------------------------------------------- validators

def fetch_validator_lists():
    """Fetch signed validator lists. Returns list of dicts, one per source.

    Each dict: {publisher, url, ok, sequence, count, expires_in_days,
    error}. Tries sources in order; records per-source errors.
    """
    out = []
    for publisher, url in VL_SOURCES:
        rec = {"publisher": publisher, "url": url, "ok": False,
               "sequence": None, "count": None, "expires_in_days": None,
               "error": None}
        try:
            vl = _http_get_json(url)
            blob = json.loads(base64.b64decode(vl["blob"]))
            validators = blob.get("validators", [])
            exp_unix = blob.get("expiration", 0) + RIPPLE_EPOCH
            rec.update(ok=True,
                       sequence=blob.get("sequence"),
                       count=len(validators),
                       expires_in_days=(exp_unix - time.time()) / 86400.0)
        except Exception as e:  # noqa: BLE001 — recorded, not raised
            rec["error"] = f"{type(e).__name__}"
        out.append(rec)
    return out


def _read_seen():
    try:
        return json.loads(SEEN_PATH.read_text())
    except Exception:  # noqa: BLE001 — first run / corrupt -> reseed
        return {}


def _write_seen(data):
    try:
        SEEN_PATH.parent.mkdir(parents=True, exist_ok=True)
        SEEN_PATH.write_text(json.dumps(data))
    except Exception:  # noqa: BLE001 — watermark is best-effort
        pass


def format_validators():
    """Chat-ready validator-list health lines. Never raises."""
    lines = ["Validator lists (signed, per publisher):"]
    try:
        recs = fetch_validator_lists()
    except Exception:  # noqa: BLE001 — fail-open
        return lines + ["  ⚠️  unavailable (network error) — try again later."]
    seen = _read_seen()
    new_seen = {}
    any_ok = False
    for r in recs:
        if not r["ok"]:
            lines.append(f"  {r['publisher']}: unreachable "
                         f"({r['error']}) — trying next source")
            continue
        any_ok = True
        days = r["expires_in_days"]
        warn = "  ⚠️  EXPIRES SOON" if days is not None and days < 30 else ""
        lines.append(f"  {r['publisher']}: {r['count']} validators, "
                     f"sequence {r['sequence']}, "
                     f"expires in {days:.0f}d{warn}")
        prev = seen.get(r["publisher"])
        cur = {"sequence": r["sequence"], "count": r["count"]}
        new_seen[r["publisher"]] = cur
        if prev and (prev.get("sequence") != cur["sequence"]
                     or prev.get("count") != cur["count"]):
            lines.append(f"    ↻ membership changed since last check "
                         f"(was seq {prev.get('sequence')}, "
                         f"{prev.get('count')} validators)")
        if r["count"] != 35:
            lines.append(f"    note: UNL voter count is 35 per livenet "
                         f"explorer; this list holds {r['count']}")
    if any_ok:
        _write_seen(new_seen)
    else:
        lines.append("  ⚠️  all validator-list sources unreachable — "
                     "try again later.")
    xline = format_xrpscan_validator_line(
        {r["publisher"]: r["count"] for r in recs if r["ok"]})
    if xline:
        lines.append(xline)
    lines.append("  per signed validator-list files (vl.ripple.com, "
                 "unl.xrplf.org); the `validators` RPC is admin-only on "
                 "public servers.")
    return lines


# ---------------------------------------------------------------- amendments

def fetch_amendments():
    """Public-RPC amendment status. Returns dict, never raises.

    {ok, features: {id: {name, enabled, supported}}, majorities: [...],
     ledger, error}
    """
    out = {"ok": False, "features": {}, "majorities": [],
           "ledger": None, "error": None}
    last = None
    for server in RPC_SERVERS:
        try:
            res = _http_post_json(server, {"method": "feature"})
            result = res.get("result", {})
            feats = result.get("features")
            if not isinstance(feats, dict):
                raise ValueError("unexpected feature response shape")
            out["features"] = feats
            out["ledger"] = result.get("ledger_index")
            try:
                si = _http_post_json(server, {"method": "server_info"})
                info = si.get("result", {}).get("info", {})
                out["majorities"] = (info.get("amendments", {})
                                         .get("majorities", []) or [])
            except Exception:  # noqa: BLE001 — majorities optional
                out["majorities"] = []
            out["ok"] = True
            return out
        except Exception as e:  # noqa: BLE001 — try next server
            last = e
    out["error"] = f"{type(last).__name__}" if last else "unknown"
    return out


def format_amendments():
    """Chat-ready amendment status lines. Never raises."""
    lines = ["Amendments (per public rippled RPC):"]
    rep = fetch_amendments()
    if not rep["ok"]:
        return lines + [f"  ⚠️  unavailable ({rep['error']}) — "
                        "try again later."]
    feats = rep["features"]
    voting = sorted(f["name"] for f in feats.values()
                    if f.get("supported") and not f.get("enabled"))
    enabled = sum(1 for f in feats.values() if f.get("enabled"))
    blocked = [f["name"] for f in feats.values()
               if f.get("enabled") and not f.get("supported")]

    if voting:
        lines.append(f"  🗳️  in voting ({len(voting)}):")
        for name in voting:
            lines.append(f"    · {name}")
    else:
        lines.append("  🗳️  in voting: none")
    lines.append(f"  ✅ enabled: {enabled} of {len(feats)} known")

    maj = rep["majorities"]
    if maj:
        lines.append("  ⏳ majority countdown:")
        for m in maj:
            aid = str(m.get("amendment", ""))
            name = next((f["name"] for i, f in feats.items() if i == aid),
                        aid[:12] + "…")
            lines.append(f"    · {name}: {m.get('count')}/35 "
                         f"since ledger {m.get('since_ledger', m.get('sinceLedger', '?'))}")
    if blocked:
        lines.append("  🚨 AMENDMENT-BLOCKED RISK on this server: "
                     + ", ".join(blocked))
    xline = format_xrpscan_amendment_line(voting)
    if xline:
        lines.append(xline)
    if rep["ledger"]:
        lines.append(f"  ledger {rep['ledger']}; 80% supermajority held "
                     "2 weeks activates an amendment.")
    return lines


# ---------------------------------------------------------------- XRPL Meta

def xrplmeta_lookup(currency, issuer):
    """Single token record from XRPL Meta. Returns dict or None. Never raises.

    Route takes the plain currency code (e.g. RLUSD), NOT hex — verified
    2026-09-30: /token/RLUSD:rMxCK... -> 200, hex form -> 400.
    """
    try:
        ccy = (currency or "").strip().upper()
        if not ccy or not issuer:
            return None
        rec = _http_get_json(
            f"{XRPLMETA_BASE}/token/{ccy}:{issuer}", timeout=15, retries=2)
        return rec if isinstance(rec, dict) else None
    except Exception:  # noqa: BLE001 — fail-open
        return None


def format_xrplmeta_lines(currency, issuer):
    """Second-opinion metadata block for token-safety. Never raises.

    Returns [] when unavailable (caller prints its own fallback) or a
    list of lines. Publisher-derived ratings are labeled as opinions.
    """
    rec = xrplmeta_lookup(currency, issuer)
    if not rec:
        return []
    lines = ["  XRPL Meta second opinion (per xrplmeta.org):"]
    meta = rec.get("meta", {}) or {}
    tok, iss = meta.get("token", {}) or {}, meta.get("issuer", {}) or {}
    if tok.get("name"):
        lines.append(f"    token: {tok['name']}")
    if iss.get("name"):
        kyc = " · KYC'd" if iss.get("kyc") else ""
        dom = f" · {iss['domain']}" if iss.get("domain") else ""
        lines.append(f"    issuer: {iss['name']}{kyc}{dom}")
    tl = tok.get("trust_level")
    if tl is not None:
        lines.append(f"    trust_level: {tl}/5 (publisher opinion, "
                     "not a ledger fact)")
    m = rec.get("metrics", {}) or {}
    try:
        holders = int(float(m.get("holders", 0)))
        tls = int(float(m.get("trustlines", 0)))
        lines.append(f"    holders: {holders:,} · trustlines: {tls:,}")
    except (TypeError, ValueError):
        pass
    px = m.get("price")
    try:
        if px is not None:
            lines.append(f"    price: {float(px):.6g} XRP")
    except (TypeError, ValueError):
        pass
    return lines


# ---------------------------------------------------------------- OnTheDEX

def onthedex_get(path, params=None):
    """Defensive GET against the OnTheDEX public API.

    Returns parsed JSON dict, or None on maintenance/error. Never raises.
    NOTE: API was in full ERROR_MAINTENANCE on 2026-09-30; shapes below
    are best-effort until re-verified on a live response.
    """
    try:
        url = ONTHEDEX_BASE + path
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            url += "?" + qs
        data = _http_get_json(url, timeout=15, retries=2)
        if isinstance(data, dict) and data.get("error"):
            return None  # e.g. ERROR_MAINTENANCE — fail silent
        return data
    except Exception:  # noqa: BLE001 — fail-open
        return None


def format_onthedex_note():
    """One-line OnTheDEX availability note for movers. Never raises."""
    tick = onthedex_get("/ticker")
    if tick is None:
        return None  # silent when down — xrpl.to remains the source
    n = len(tick) if isinstance(tick, dict) else 0
    return (f"  OnTheDEX cross-check: live ({n} tickers) — "
            "per api.onthedex.live")


# ---------------------------------------------------------------- xrpscan (fallback)

def xrpscan_validators_count():
    """Validator count per xrpscan. Returns int or None. Never raises."""
    try:
        data = _http_get_json(f"{XRPSCAN_BASE}/validators",
                              timeout=15, retries=2)
        return len(data) if isinstance(data, list) else None
    except Exception:  # noqa: BLE001 — fallback is optional
        return None


def xrpscan_amendments_voting():
    """Amendment names in voting per xrpscan. Returns list or None."""
    try:
        data = _http_get_json(f"{XRPSCAN_BASE}/amendments",
                              timeout=15, retries=2)
        if not isinstance(data, list):
            return None
        return sorted(a.get("name", "?") for a in data
                      if isinstance(a, dict)
                      and a.get("supported") and not a.get("enabled"))
    except Exception:  # noqa: BLE001 — fallback is optional
        return None


def format_xrpscan_validator_line(our_counts):
    """Cross-check line for format_validators. our_counts: {pub: count}."""
    n = xrpscan_validators_count()
    if n is None:
        return None
    agree = any(c == n for c in our_counts.values()) if our_counts else False
    # xrpscan tracks every validator it sees on the network; the signed
    # lists are the UNL roster — a higher xrpscan count is expected.
    verdict = ("agrees with signed lists" if agree
               else "network-wide registry (signed lists are the UNL roster)")
    return (f"  xrpscan cross-check: tracks {n} validators — {verdict} "
            f"{XRPSCAN_NOTE}")


def format_xrpscan_amendment_line(our_voting):
    """Cross-check line for format_amendments. our_voting: [names]."""
    names = xrpscan_amendments_voting()
    if names is None:
        return None
    ours, theirs = set(our_voting or []), set(names)
    if ours == theirs:
        verdict = "agrees"
    else:
        diff = sorted((ours ^ theirs))[:4]
        verdict = f"differs on: {', '.join(diff)}"
    return (f"  xrpscan cross-check: {len(names)} in voting ({verdict}) "
            f"{XRPSCAN_NOTE}")


# ---------------------------------------------------------------- DefiLlama

def defillama_stablecoin(symbol):
    """Stablecoin record from DefiLlama. Returns dict or None. Never raises."""
    try:
        data = _http_get_json(f"{DEFILLAMA_STABLE}/stablecoins"
                              "?includePrices=true", timeout=20, retries=2)
        assets = (data or {}).get("peggedAssets", [])
        sym = (symbol or "").upper()
        for a in assets:
            if isinstance(a, dict) and str(a.get("symbol", "")).upper() == sym:
                return a
        return None
    except Exception:  # noqa: BLE001 — fail-open
        return None


def format_stablecoin(symbol="RLUSD"):
    """Chat-ready stablecoin brief. Never raises."""
    sym = (symbol or "RLUSD").upper()
    lines = [f"Stablecoin [{sym}] (per DefiLlama):"]
    rec = defillama_stablecoin(sym)
    if not rec:
        return lines + ["  ⚠️  unavailable or unknown symbol — "
                        "try again later."]
    try:
        price = float(rec.get("price"))
        lines.append(f"  price: ${price:.4f}")
    except (TypeError, ValueError):
        pass
    chains = rec.get("chainCirculating") or {}
    total, rows = 0.0, []
    for chain, info in chains.items():
        try:
            cur = float((info.get("current") or {}).get("peggedUSD", 0))
        except (TypeError, ValueError):
            continue
        total += cur
        rows.append((chain, cur))
    rows.sort(key=lambda r: -r[1])
    if total > 0:
        lines.append(f"  total circulating: {_fmt_usd(total)}")
        for chain, cur in rows:
            lines.append(f"    · {chain}: {_fmt_usd(cur)} "
                         f"({cur/total*100:.1f}%)")
        xrpl = next((c for ch, c in rows if ch.upper() == "XRPL"), 0)
        if xrpl:
            lines.append(f"  XRPL share: {xrpl/total*100:.1f}% of supply")
    lines.append("  per DefiLlama (aggregator, not ledger authority) — "
                 "cross-chain supply ≠ XRPL-native supply; verify "
                 "XRPL-native figures on-ledger.")
    return lines


# ---------------------------------------------------------------- price oracles (XLS-47)

# Verified publisher identities. Band's address is published in Band
# Protocol's XRPL mainnet launch post (blog.bandprotocol.com); DIA's in
# the XRPLF dev portal ("Integrating DIA Oracles on the XRP Ledger",
# 2025-05-16). Doc IDs from the same sources. Publisher-attested data
# is an opinion, not ledger truth — always label the publisher.
ORACLE_PUBLISHERS = [
    {"name": "Band Protocol",
     "account": "rsNvoAZ9MquZSRhu4cEY9wTv1VqHXpVPPt",
     "oracle_document_id": 1},
    {"name": "DIA",
     "account": "rP24Lp7bcUHvEW7T7c8xkxtQKKd9fZyra7",
     "oracle_document_id": 42},
]

# Warn when a publisher's feed is older than this (DIA's heartbeat is
# 24h; anything past it plus a margin means updates stopped).
ORACLE_STALE_AFTER_SECS = 26 * 3600


def _rpc(method, params):
    """Call a public rippled method across RPC_SERVERS in order.

    Returns the result dict. Raises on total failure (caller decides
    how to fail open).
    """
    last = None
    for url in RPC_SERVERS:
        try:
            res = _http_post_json(url, {"method": method, "params": [params]})
        except Exception as e:  # noqa: BLE001 — try next server
            last = e
            continue
        if isinstance(res, dict) and res.get("result", {}).get("status") \
                in ("success", None) and "error" not in res.get("result", {}):
            return res["result"]
        last = RuntimeError(str(res)[:120])
    raise last if last else RuntimeError("no RPC servers configured")


def decode_oracle_price(asset_price, scale):
    """Decode an XLS-47 AssetPrice hex string at Scale -> float.

    Raises ValueError on bad input.
    """
    raw = str(asset_price).strip()
    if raw.lower().startswith("0x"):
        raw = raw[2:]
    return int(raw, 16) / (10 ** int(scale))


def _hex_label(ccy):
    """Human label for a ledger-form currency: 'RLUSD' for its hex."""
    c = (ccy or "").strip()
    if len(c) == 40:
        try:
            text = bytes.fromhex(c).rstrip(b"\x00").decode("ascii")
            if text and all(32 < ord(ch) < 127 for ch in text):
                return text
        except (ValueError, UnicodeDecodeError):
            pass
        return c[:8] + "…"
    return c


def fetch_oracle_object(account, oracle_document_id):
    """Fetch one publisher's Oracle ledger object (dict) or None.

    Never raises. LastUpdateTime is unix seconds.
    """
    try:
        res = _rpc("account_objects",
                   {"account": account, "type": "oracle", "limit": 20})
    except Exception:  # noqa: BLE001 — fail-open
        return None
    objs = [o for o in res.get("account_objects", [])
            if isinstance(o, dict)]
    for o in objs:
        if o.get("OracleDocumentID") == oracle_document_id:
            return o
    return objs[0] if objs else None


def oracle_series_price(obj, base_hex, quote_hex):
    """Price + LastUpdateTime for a base/quote pair from an Oracle object.

    Returns (value_or_None, last_update_or_None). Never raises.
    """
    try:
        last_update = obj.get("LastUpdateTime")
        for s in obj.get("PriceDataSeries", []):
            if not isinstance(s, dict):
                continue
            pd = s.get("PriceData", {})
            ba, qa = pd.get("BaseAsset", {}), pd.get("QuoteAsset", {})
            b = ba.get("currency") if isinstance(ba, dict) else ba
            q = qa.get("currency") if isinstance(qa, dict) else qa
            if str(b).upper() == str(base_hex).upper() \
                    and str(q).upper() == str(quote_hex).upper():
                return decode_oracle_price(pd.get("AssetPrice"),
                                           pd.get("Scale")), last_update
        return None, last_update
    except Exception:  # noqa: BLE001 — fail-open
        return None, None


def _fmt_age(secs):
    if secs is None or secs < 0:
        return "age unknown"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{secs / 3600:.0f}h ago"
    return f"{secs / 86400:.1f}d ago"


def format_oracle(base="XRP", quote="USD"):
    """On-ledger XLS-47 oracle prices: per-publisher + aggregate median.

    Primary price source is the ledger itself (Band Protocol + DIA
    publishers); no exchange API involved. Advisory + fail-open: RPC
    failures return 'unavailable' lines, never raise.
    """
    b_in = (base or "XRP").strip().upper()
    q_in = (quote or "USD").strip().upper()
    b_hex, q_hex = currency_to_hex(b_in), currency_to_hex(q_in)
    pair = f"{b_in}/{q_in}"
    lines = [f"  XLS-47 on-ledger price oracles for {pair}:"]
    now = int(time.time())
    pubs = []
    try:
        for pub in ORACLE_PUBLISHERS:
            obj = fetch_oracle_object(pub["account"],
                                      pub["oracle_document_id"])
            if obj is None:
                lines.append(f"    {pub['name']}: feed unreachable "
                             f"(treat as UNKNOWN)")
                continue
            value, updated = oracle_series_price(obj, b_hex, q_hex)
            pubs.append(pub)
            if value is None:
                lines.append(f"    {pub['name']}: no {pair} series published")
                continue
            age = now - updated if updated else None
            lines.append(f"    {pub['name']}: {pair} = "
                         f"${value:,.6f} (updated {_fmt_age(age)})")
            if age is not None and age > ORACLE_STALE_AFTER_SECS:
                lines.append(f"      ⚠️  {pub['name']} feed stale "
                             f"(>{ORACLE_STALE_AFTER_SECS // 3600}h "
                             f"without update)")
    except Exception:  # noqa: BLE001 — fail-open
        return [f"  oracle feed unavailable for {pair} "
                "(rippled unreachable) — treat as UNKNOWN."]
    if pubs:
        try:
            agg = _rpc("get_aggregate_price", {
                "ledger_index": "current",
                "base_asset": b_hex, "quote_asset": q_hex, "trim": 20,
                "oracles": [{"account": p["account"],
                             "oracle_document_id": p["oracle_document_id"]}
                            for p in pubs]})
            entire = agg.get("entire_set") or {}
            tset = agg.get("trimmed_set") or {}
            med = agg.get("median")
            if med is not None:
                lines.append(f"    aggregate median: ${float(med):,.6f} "
                             f"(mean ${float(entire.get('mean', med)):,.6f}, "
                             f"{entire.get('size', '?')} publishers)")
                if tset.get("mean") is not None:
                    lines.append(f"    trimmed mean (20%): "
                                 f"${float(tset['mean']):,.6f}")
        except Exception:  # noqa: BLE001 — aggregate optional
            lines.append("    aggregate unavailable (per-publisher "
                         "prices above still stand)")
    lines.append("  publisher-attested prices, not ledger truth; "
                 "Band + DIA identities per their published docs.")
    return lines


# ---------------------------------------------------------------- DEX Screener

def dexscreener_xrpl_pair(currency, issuer):
    """Best XRPL pair for a token per DEX Screener.

    Returns pair dict or None. Never raises. Match rule: chainId ==
    "xrpl" AND (baseToken.symbol == currency OR issuer in pairAddress).
    """
    try:
        q = urllib.parse.quote((currency or "").strip())
        if not q:
            return None
        data = _http_get_json(f"{DEXSCREENER_BASE}/latest/dex/search?q={q}",
                              timeout=15, retries=2)
        pairs = (data or {}).get("pairs", [])
        ccy = (currency or "").upper()
        best, best_liq = None, -1.0
        for p in pairs:
            if not isinstance(p, dict) or p.get("chainId") != "xrpl":
                continue
            base = p.get("baseToken") or {}
            sym_ok = str(base.get("symbol", "")).upper() == ccy
            iss_ok = issuer and issuer in str(p.get("pairAddress", ""))
            if not (sym_ok or iss_ok):
                continue
            try:
                liq = float((p.get("liquidity") or {}).get("usd", 0))
            except (TypeError, ValueError):
                liq = 0
            if liq > best_liq:
                best, best_liq = p, liq
        return best
    except Exception:  # noqa: BLE001 — fail-open
        return None


def format_dexscreener_lines(currency, issuer):
    """XRPL pair cross-check block for token-safety. Never raises."""
    p = dexscreener_xrpl_pair(currency, issuer)
    if not p:
        return []
    lines = ["  DEX Screener XRPL cross-check (per dexscreener.com):"]
    try:
        lines.append(f"    price: ${float(p['priceUsd']):.6g}")
    except (TypeError, ValueError, KeyError):
        pass
    liq = (p.get("liquidity") or {}).get("usd")
    if liq is not None:
        lines.append(f"    liquidity: {_fmt_usd(liq)}")
    vol = (p.get("volume") or {}).get("h24")
    if vol is not None:
        lines.append(f"    24h volume: {_fmt_usd(vol)}")
    txns = (p.get("txns") or {}).get("h24") or {}
    if txns:
        lines.append(f"    24h txns: {txns.get('buys', '?')} buys / "
                     f"{txns.get('sells', '?')} sells")
    chg = (p.get("priceChange") or {}).get("h24")
    try:
        lines.append(f"    24h change: {float(chg):+,.2f}%")
    except (TypeError, ValueError):
        pass
    lines.append(f"    pair: {p.get('dexId', '?')} "
                 f"{str(p.get('pairAddress', ''))[:40]}…")
    lines.append("    aggregator data, not ledger authority.")
    return lines
