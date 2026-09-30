#!/usr/bin/env python3
"""xrpl.to API client for the XRPL skill.

Read-only market intel: scam checks + token risk scores, wired into the
pre-trade proposal path so the human sees them BEFORE approving anything.

Security posture:
  - Read calls never sign, never submit, never need a seed.
  - Pure stdlib (urllib) — no new dependencies.
  - Fail-OPEN on API errors: a scam check that cannot be reached prints a
    loud "UNAVAILABLE" warning but never blocks a proposal. The human, the
    existing inspect-token ceremony, and the signer policy remain the gates.
    A positive scam hit is LOUD but advisory — it never auto-blocks, because
    blocklists can false-positive on legitimate tokens.
  - API key (optional) lives in ~/.xrpl/xrplto.json (0600, atomic write) or
    the XRPLTO_API_KEY env var. Most endpoints work without a key.
  - `keys create` performs a wallet-signed login-style message signature
    with the operator's OWN local key to mint a free API key. It is NOT a
    ledger transaction (nothing is submitted), requires explicit --yes, and
    prints the exact message to be signed first. The seed never leaves the
    machine and never appears in output.
  - Attribution: any surface showing xrpl.to data must carry a visible
    "Data by xrpl.to" credit (their terms). format_safety_lines() includes it.

Docs: https://xrpl.to/docs  |  API: https://api.xrpl.to/v1
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

try:
    import xrpl_eco
except ImportError:
    xrpl_eco = None  # XRPL Meta second opinion unavailable; xrpl.to unaffected

API_BASE = "https://api.xrpl.to/v1"
USER_AGENT = "xrpl-muse-skill/0.9.0 (+https://github.com/terramike/xrpl-muse-skill)"
KEY_PATH = Path.home() / ".xrpl" / "xrplto.json"
ATTRIBUTION = "Data by xrpl.to (https://xrpl.to)"

# ---------------------------------------------------------------------------
# key management
# ---------------------------------------------------------------------------

def load_api_key():
    """API key from env or ~/.xrpl/xrplto.json. Returns None if unset."""
    env = os.environ.get("XRPLTO_API_KEY")
    if env:
        return env.strip()
    try:
        data = json.loads(KEY_PATH.read_text())
        return (data.get("api_key") or "").strip() or None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def save_api_key(key):
    """Atomic 0600 write of the API key. Never prints the key."""
    KEY_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = KEY_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps({"api_key": key, "created_at": int(time.time())}))
    os.chmod(tmp, 0o600)
    os.replace(tmp, KEY_PATH)


def remove_api_key():
    try:
        KEY_PATH.unlink()
        return True
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def _headers(extra=None):
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    key = load_api_key()
    if key:
        h["X-Api-Key"] = key
    if extra:
        h.update(extra)
    return h


def api_get(path, params=None, timeout=12):
    """GET a JSON endpoint. Returns parsed dict, or None on any failure.

    Fail-open by design: network errors, 4xx/5xx, bad JSON all -> None.
    Callers must treat None as 'check unavailable', never as 'clean'.
    """
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def api_post(path, body, extra_headers=None, timeout=15):
    """POST JSON. Returns (status_code, parsed_dict_or_None)."""
    data = json.dumps(body).encode("utf-8")
    h = _headers(extra_headers)
    h["Content-Type"] = "application/json"
    req = urllib.request.Request(API_BASE + path, data=data, headers=h,
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"_raw": raw}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, None
    except Exception:
        return 0, None


# ---------------------------------------------------------------------------
# intel: scam check + token risk score
# ---------------------------------------------------------------------------

def scam_check(issuer):
    """GET /scams/check/{account}. Returns dict or None (unavailable)."""
    if not issuer:
        return None
    return api_get(f"/scams/check/{issuer}")


def token_lookup(issuer, currency):
    """GET /token/{issuer}_{currency} -> token dict or None.

    The {id} may be issuer_currency with the plain (>3 char codes work as
    given); falls back to the 40-char hex currency form.
    """
    ccy = (currency or "").upper()
    for cur in (ccy, ccy.encode().hex().upper().ljust(40, "0")):
        r = api_get(f"/token/{issuer}_{cur}")
        if r and r.get("success") and r.get("token"):
            return r["token"]
    return None


def token_review(md5):
    """GET /token/review/{md5} -> review dict or None."""
    if not md5:
        return None
    r = api_get(f"/token/review/{md5}")
    if r and r.get("score") is not None:
        return r
    return None


def safety_report(issuer, currency):
    """Combined scam + risk report for one IOU. Never raises.

    Returns dict with keys: issuer, currency, scam (dict|None),
    review (dict|None), unavailable (bool).
    """
    rep = {"issuer": issuer, "currency": (currency or "").upper(),
           "scam": None, "review": None, "unavailable": False}
    try:
        rep["scam"] = scam_check(issuer)
        tok = token_lookup(issuer, currency)
        if tok:
            rep["review"] = token_review(tok.get("_id"))
        if rep["scam"] is None and rep["review"] is None:
            rep["unavailable"] = True
    except Exception:
        rep["unavailable"] = True
    return rep


def _risk_emoji(score):
    try:
        s = int(score)
    except (TypeError, ValueError):
        return "❓"
    if s <= 3:
        return "🟢"
    if s <= 6:
        return "🟡"
    return "🔴"


def format_safety_lines(issuer, currency):
    """Proposal-ready lines for one IOU leg. Includes attribution.

    A positive scam hit is printed LOUD but stays advisory — the human
    decides; blocklists can false-positive.
    """
    rep = safety_report(issuer, currency)
    ccy = rep["currency"]
    lines = [f"safety [{ccy}.{issuer[:8]}…]:"]
    if rep["unavailable"]:
        lines.append("  ⚠️  xrpl.to safety check UNAVAILABLE (network/API error) —")
        lines.append("      treat as UNKNOWN, not clean. Review manually.")
        lines.append(f"  {ATTRIBUTION}")
        return lines
    scam = rep["scam"] or {}
    if scam.get("is_scam"):
        lines.append("  🚨 SCAM FLAG: this issuer is on the xrpl.to scam blocklist")
        lvl = scam.get("risk_level")
        if lvl:
            lines.append(f"      risk_level: {lvl}")
    else:
        rl = scam.get("risk_level", "unknown")
        lines.append(f"  scam blocklist: not flagged (risk_level: {rl})")
    rev = rep["review"]
    if rev:
        score, level = rev.get("score"), rev.get("riskLevel", "?")
        lines.append(f"  risk score: {_risk_emoji(score)} {score}/10 ({level}) — "
                     f"{rev.get('riskCount', '?')} risk / "
                     f"{rev.get('positiveCount', '?')} positive signals")
    else:
        lines.append("  risk score: unavailable for this token")
    if xrpl_eco is not None:
        try:
            lines.extend(xrpl_eco.format_xrplmeta_lines(ccy, issuer))
        except Exception:  # noqa: BLE001 — second opinion is optional
            pass
        try:
            lines.extend(xrpl_eco.format_dexscreener_lines(ccy, issuer))
        except Exception:  # noqa: BLE001 — cross-check is optional
            pass
    lines.append(f"  {ATTRIBUTION}")
    return lines


def check_pair_legs(base, base_issuer, quote, quote_issuer):
    """Safety lines for every non-XRP leg of a trade pair."""
    lines = []
    for ccy, iss in ((base, base_issuer), (quote, quote_issuer)):
        if iss:  # XRP has no issuer — nothing to check
            lines.extend(format_safety_lines(iss, ccy))
    return lines


# ---------------------------------------------------------------------------
# NFT buy-side safety: scam screen + collection floor for proposals
# ---------------------------------------------------------------------------

def _xrp_float(v):
    """Best-effort XRP float from an xrpl.to amount field.

    Handles XRP numbers, {"currency": "XRP", "value": ...} dicts, and
    drops strings (all-digit strings are drops — matches the ledger-derived
    fields this API returns). Returns None when the value is unclear.
    """
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, dict):
        if str(v.get("currency", "XRP")).upper() != "XRP":
            return None
        return _xrp_float(v.get("value"))
    if isinstance(v, str):
        s = v.strip().replace(",", "")
        if not s:
            return None
        try:
            if s.isdigit():
                return int(s) / 1_000_000  # drops
            return float(s)
        except ValueError:
            return None
    try:
        return float(v)  # int, float, Decimal, ...
    except (TypeError, ValueError):
        return None


def _xrp_units(v):
    """Parse a caller-supplied amount already denominated in XRP.

    Unlike _xrp_float (for API fields that may be drops strings), a plain
    digit string here means XRP — e.g. --ask-xrp 40 is 40 XRP, not 40 drops.
    """
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, str):
        try:
            return float(v.strip().replace(",", ""))
        except ValueError:
            return None
    return _xrp_float(v)


def nft_detail(nft_id):
    """GET /nft/{nftId} -> dict or None. Never raises."""
    if not nft_id or len(str(nft_id)) != 64:
        return None
    try:
        r = api_get(f"/nft/{nft_id}")
    except Exception:
        return None
    return r if isinstance(r, dict) and r.get("NFTokenID") else None


def nft_collection_for(issuer, taxon):
    """Resolve issuer+taxon -> collection dict or None."""
    if not issuer or taxon is None:
        return None
    try:
        r = api_get("/nft/collections/resolve",
                    {"account": issuer, "taxon": taxon})
    except Exception:
        return None
    c = (r or {}).get("collection") if isinstance(r, dict) else None
    return c if isinstance(c, dict) and c.get("slug") else None


def nft_collection_floor(slug):
    """(floor_xrp, floor_24h_ago_xrp); (None, None) when unknown."""
    if not slug:
        return None, None
    try:
        r = api_get(f"/nft/collections/{slug}/metrics")
    except Exception:
        return None, None
    m = (r or {}).get("metrics") if isinstance(r, dict) else None
    if not isinstance(m, dict):
        return None, None
    return _xrp_float(m.get("floor")), _xrp_float(m.get("floor24hAgo"))


def nft_live_asks(nft_id):
    """Live sell-offer asks for one NFT, ascending XRP. [] when none."""
    try:
        r = api_get(f"/nft/offers/sell/{nft_id}")
    except Exception:
        return []
    offers = (r or {}).get("offers") if isinstance(r, dict) else None
    if not isinstance(offers, list):
        return []
    asks = []
    for o in offers:
        if isinstance(o, dict):
            a = _xrp_float(o.get("amount"))
            if a is not None and a > 0:
                asks.append(a)
    return sorted(asks)


def nft_last_sale_xrp(nft_id, limit=25):
    """Approx last sale price (XRP) from on-chain history, or None.

    Scans newest-first for NFTokenAcceptOffer and derives the price from
    the buyer's XRP balance decrease minus the tx fee. Gifts and wash
    trades read as ~0 — callers must label the figure approximate and
    advisory, never an appraisal.
    """
    try:
        r = api_get(f"/nft/history/{nft_id}", {"limit": limit})
    except Exception:
        return None
    txs = (r or {}).get("transactions") if isinstance(r, dict) else None
    if not isinstance(txs, list):
        return None
    for e in txs:
        if not isinstance(e, dict):
            continue
        tx = e.get("tx")
        if not isinstance(tx, dict):
            continue
        if tx.get("TransactionType") != "NFTokenAcceptOffer":
            continue
        fee = _xrp_float(tx.get("Fee")) or 0.0
        spent = 0.0
        meta = e.get("meta")
        nodes = (meta or {}).get("AffectedNodes") \
            if isinstance(meta, dict) else None
        if not isinstance(nodes, list):
            continue
        for n in nodes:
            mod = (n or {}).get("ModifiedNode") \
                if isinstance(n, dict) else None
            if not isinstance(mod, dict):
                continue
            if mod.get("LedgerEntryType") != "AccountRoot":
                continue
            ff = mod.get("FinalFields") or {}
            pf = mod.get("PreviousFields") or {}
            b0 = _xrp_float(pf.get("Balance"))
            b1 = _xrp_float(ff.get("Balance"))
            if b0 is not None and b1 is not None and b1 < b0:
                spent = max(spent, b0 - b1)
        if spent > 0:
            return max(spent - fee, 0.0)
    return None


def nft_safety_report(nft_id):
    """Combined NFT buy-side safety report. Never raises.

    Returns dict with keys: nft_id, issuer, taxon, scam (dict|None),
    collection_name, slug, floor_xrp, floor_24h_ago, cheapest_ask_xrp,
    last_sale_xrp, unavailable (bool — only when the NFT itself can't be
    identified; partial intel is still reported, never hidden).
    """
    rep = {"nft_id": nft_id, "issuer": None, "taxon": None, "scam": None,
           "collection_name": None, "slug": None, "floor_xrp": None,
           "floor_24h_ago": None, "cheapest_ask_xrp": None,
           "last_sale_xrp": None, "unavailable": False}
    try:
        nft = nft_detail(nft_id)
        if not nft:
            rep["unavailable"] = True
            return rep
        issuer = nft.get("issuer")
        try:
            taxon = int(nft["taxon"]) if nft.get("taxon") is not None else None
        except (TypeError, ValueError):
            taxon = None
        rep["issuer"], rep["taxon"] = issuer, taxon
        rep["scam"] = scam_check(issuer)
        col = nft_collection_for(issuer, taxon)
        if col:
            rep["collection_name"] = col.get("name")
            rep["slug"] = col.get("slug")
            rep["floor_xrp"], rep["floor_24h_ago"] = \
                nft_collection_floor(col["slug"])
        asks = nft_live_asks(nft_id)
        if asks:
            rep["cheapest_ask_xrp"] = asks[0]
        rep["last_sale_xrp"] = nft_last_sale_xrp(nft_id)
    except Exception:
        rep["unavailable"] = True
    return rep


def format_nft_safety_lines(nft_id, ask_xrp=None):
    """Proposal-ready NFT safety lines. Includes attribution.

    ask_xrp: asking/bid price in XRP (Decimal/float/str) for the
    floor-multiple line. A scam hit is printed LOUD but stays advisory —
    the human decides; blocklists can false-positive.
    """
    rep = nft_safety_report(nft_id)
    nid = str(nft_id or "")
    lines = [f"NFT safety [{nid[:8]}…]:"]
    if rep["unavailable"]:
        lines.append("  ⚠️  xrpl.to NFT safety UNAVAILABLE (network/API error) —")
        lines.append("      treat as UNKNOWN, not clean. Review manually.")
        lines.append(f"  {ATTRIBUTION}")
        return lines
    scam = rep["scam"] or {}
    issuer = rep["issuer"] or "?"
    if scam.get("is_scam"):
        lines.append("  🚨 SCAM FLAG: this issuer is on the xrpl.to scam "
                     "blocklist")
        lines.append("      advisory — blocklists can false-positive. Verify")
        lines.append("      the issuer is the artist you expect before "
                     "approving.")
    else:
        rl = scam.get("risk_level", "unknown")
        lines.append(f"  issuer {issuer[:10]}…: not on scam blocklist "
                     f"(risk_level: {rl}) ✅")
    if rep["collection_name"]:
        fl = f"{rep['floor_xrp']:.4g} XRP" \
            if rep["floor_xrp"] is not None else "n/a"
        fl24 = f", 24h ago {rep['floor_24h_ago']:.4g}" \
            if rep["floor_24h_ago"] is not None else ""
        lines.append(f"  collection: {rep['collection_name']} — "
                     f"floor {fl}{fl24}")
        ask = _xrp_units(ask_xrp)
        if ask and rep["floor_xrp"]:
            lines.append(f"  asking {ask:.4g} XRP = "
                         f"{ask / rep['floor_xrp']:.2f}× floor")
    else:
        lines.append("  collection: not tracked on xrpl.to "
                     "(1-of-1 or new issuer)")
    if rep["cheapest_ask_xrp"] is not None:
        lines.append(f"  cheapest live ask: {rep['cheapest_ask_xrp']:.4g} XRP")
    if rep["last_sale_xrp"] is not None:
        ls = rep["last_sale_xrp"]
        if ls < 0.000001:  # sub-drop dust: a transfer/gift, not a priced sale
            lines.append("  last sale: ≈ 0 XRP (transfer/gift — not a priced "
                         "sale)")
        else:
            lines.append(f"  last sale: ≈ {ls:.4g} XRP "
                         "(from ledger history — wash trades possible)")
    lines.append(f"  {ATTRIBUTION}")
    return lines


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Menu reads (Phase 2): movers, token lookup, tx-explain, top collections.
# All read-only, all carry the attribution credit.
# ---------------------------------------------------------------------------

def _fmt_big(v):
    """Compact human number: 1,234 / 12.50 / 0.000007866 / n/a."""
    if v is None:
        return "n/a"
    try:
        f = float(v)
    except (TypeError, ValueError):
        return "n/a"
    if f >= 1000:
        return f"{f:,.0f}"
    if f >= 1:
        return f"{f:,.2f}"
    return f"{f:.4g}"


def _unavailable_lines(title):
    return [title,
            "  ⚠️  xrpl.to data UNAVAILABLE (network/API error) —",
            "      treat as UNKNOWN, not as a signal. Try again later.",
            f"  {ATTRIBUTION}"]


MOVER_VIEWS = {
    "gainers": ("pro24h", "desc", "Top gainers (24h %)"),
    "losers": ("pro24h", "asc", "Top losers (24h %)"),
    "volume": ("vol24hxrp", "desc", "Most traded (24h volume)"),
    "trending": ("trendingScore", "desc", "Trending tokens"),
}


def movers(view="gainers", limit=10):
    """Ranked token lists. Never raises. Returns (view, rows|None)."""
    sort, order, _t = MOVER_VIEWS.get(view, MOVER_VIEWS["gainers"])
    try:
        limit = max(1, min(int(limit), 100))
    except (TypeError, ValueError):
        limit = 10
    try:
        r = api_get("/tokens", {"limit": limit, "sort": sort,
                                "order": order, "lightweight": True})
    except Exception:
        return view, None
    toks = (r or {}).get("tokens") if isinstance(r, dict) else None
    return view, toks if isinstance(toks, list) else None


def format_movers(view="gainers", limit=10):
    """Chat/menu-ready mover rows. Volume + mcap on every row so a
    micro-cap spike reads as what it is — discovery, not advice."""
    view, toks = movers(view, limit)
    title = MOVER_VIEWS.get(view, MOVER_VIEWS["gainers"])[2] + ":"
    if toks is None:
        return _unavailable_lines(title)
    lines = [title]
    if not toks:
        lines.append("  (no tokens returned)")
    for i, t in enumerate(toks, 1):
        if not isinstance(t, dict):
            continue
        name = t.get("name") or t.get("currency") or "?"
        price = _xrp_float(t.get("exch"))
        chg = t.get("pro24h")
        try:
            chg_s = f"{float(chg):+,.2f}%"
        except (TypeError, ValueError):
            chg_s = "n/a"
        vol = _fmt_big(_xrp_float(t.get("vol24hxrp")))
        mc = _fmt_big(_xrp_float(t.get("marketcap")))
        px = f"{price:.4g} XRP" if price is not None else "n/a"
        lines.append(f"  {i}. {name} · {px} · {chg_s} 24h · "
                     f"vol {vol} XRP · mcap {mc} XRP")
    if xrpl_eco is not None:
        try:
            note = xrpl_eco.format_onthedex_note()
            if note:
                lines.append(note)
        except Exception:  # noqa: BLE001 — cross-check is optional
            pass
    lines.append(f"  {ATTRIBUTION}")
    return lines


def token_lookup_report(issuer, currency):
    """Token detail + safety in one report. Never raises."""
    rep = {"issuer": issuer, "currency": (currency or "").upper(),
           "token": None, "safety": None, "unavailable": False}
    try:
        tok = token_lookup(issuer, currency)
        if not tok:
            rep["unavailable"] = True
            return rep
        rep["token"] = tok
        rep["safety"] = safety_report(issuer, currency)
    except Exception:
        rep["unavailable"] = True
    return rep


def format_token_lookup(issuer, currency):
    """One-screen token brief: market facts + safety. Includes attribution."""
    rep = token_lookup_report(issuer, currency)
    ccy = rep["currency"]
    title = f"Token [{ccy}.{issuer[:8]}…]:"
    if rep["unavailable"] or not rep["token"]:
        return _unavailable_lines(title)
    t = rep["token"]
    lines = [title]
    name = t.get("name") or ccy
    ver = " ✅ verified" if t.get("verified") else ""
    lines.append(f"  {name}{ver}")
    px = _xrp_float(t.get("exch"))
    usd = _xrp_float(t.get("usd"))
    if px is not None:
        lines.append(f"  price: {px:.4g} XRP"
                     + (f" (${usd:.4g})" if usd else ""))
    mc = _xrp_float(t.get("marketcap"))
    if mc is not None:
        lines.append(f"  market cap: {_fmt_big(mc)} XRP")
    holders, tls = t.get("holders"), t.get("trustlines")
    if holders is not None:
        try:
            hl = f"  holders: {int(holders):,}"
            if tls is not None:
                hl += f"   trustlines: {int(tls):,}"
            lines.append(hl)
        except (TypeError, ValueError):
            pass
    for key, label in (("pro24h", "24h"), ("pro7d", "7d")):
        try:
            lines.append(f"  change {label}: {float(t[key]):+,.2f}%")
        except (TypeError, ValueError, KeyError):
            pass
    vol = _xrp_float(t.get("vol24hxrp"))
    if vol is not None:
        lines.append(f"  24h volume: {_fmt_big(vol)} XRP")
    # safety, compact (reuses the same backend as token-safety)
    s = rep["safety"] or {}
    scam = s.get("scam") or {}
    if scam.get("is_scam"):
        lines.append("  🚨 SCAM FLAG: issuer on the xrpl.to scam blocklist "
                     "(advisory)")
    else:
        lines.append(f"  scam blocklist: not flagged "
                     f"(risk_level: {scam.get('risk_level', 'unknown')}) ✅")
    rev = s.get("review")
    if rev:
        lines.append(f"  risk score: {_risk_emoji(rev.get('score'))} "
                     f"{rev.get('score')}/10 ({rev.get('riskLevel', '?')})")
    if xrpl_eco is not None:
        try:
            lines.extend(xrpl_eco.format_xrplmeta_lines(
                rep["currency"], rep["issuer"]))
        except Exception:  # noqa: BLE001 — second opinion is optional
            pass
    lines.append(f"  {ATTRIBUTION}")
    return lines


def tx_explain_report(tx_hash):
    """GET /tx-explain/{hash} -> dict or None. Never raises."""
    if not tx_hash:
        return None
    try:
        r = api_get(f"/tx-explain/{tx_hash}")
    except Exception:
        return None
    return r if isinstance(r, dict) else None


def format_tx_explain(tx_hash):
    """Ledger-derived tx facts. The API's plain-English summary is shown
    only when actually present — never invented."""
    h = (tx_hash or "").strip()
    title = f"Transaction [{h[:8]}…]:"
    if len(h) != 64 or any(c not in "0123456789abcdefABCDEF" for c in h):
        return [title, "  not a valid 64-hex transaction hash"]
    rep = tx_explain_report(h)
    if not rep:
        return _unavailable_lines(title)
    ex = rep.get("extracted") or {}
    lines = [title,
             f"  type:    {ex.get('type', '?')}",
             f"  account: {ex.get('account', '?')}",
             f"  status:  {ex.get('status', '?')}"]
    if ex.get("fee"):
        lines.append(f"  fee:     {ex['fee']}")
    if ex.get("date"):
        lines.append(f"  date:    {ex['date']}")
    summ = rep.get("summary") or {}
    s = summ.get("summary")
    if s and s != "AI summary unavailable":
        lines.append(f"  summary: {s}")
        for kp in summ.get("keyPoints") or []:
            lines.append(f"    • {kp}")
    else:
        lines.append("  (plain-English summary unavailable from xrpl.to — "
                     "the facts above are ledger-derived)")
    lines.append(f"  {ATTRIBUTION}")
    return lines


TOP_COLLECTION_SORTS = {
    "vol24h": "Top NFT collections (24h volume)",
    "totalVol24h": "Top NFT collections (total 24h volume)",
    "trendingScore": "Trending NFT collections",
}


def top_collections(sort="vol24h", limit=10):
    """Ranked NFT collections. Never raises. Returns (sort, rows|None)."""
    if sort not in TOP_COLLECTION_SORTS:
        sort = "vol24h"
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 10
    try:
        r = api_get("/nft/collections",
                    {"limit": limit, "sort": sort, "order": "desc"})
    except Exception:
        return sort, None
    cols = (r or {}).get("collections") if isinstance(r, dict) else None
    return sort, cols if isinstance(cols, list) else None


def format_top_collections(sort="vol24h", limit=10):
    """Chat/menu-ready collection rows with floors. Includes attribution."""
    sort, cols = top_collections(sort, limit)
    title = TOP_COLLECTION_SORTS[sort] + ":"
    if cols is None:
        return _unavailable_lines(title)
    lines = [title]
    if not cols:
        lines.append("  (no collections returned)")
    for i, c in enumerate(cols, 1):
        if not isinstance(c, dict):
            continue
        name = c.get("name") or c.get("slug") or "?"
        floor = _xrp_float(c.get("floor"))
        vol = _fmt_big(_xrp_float(c.get("vol24h")))
        owners = c.get("owners")
        sales = c.get("sales24h")
        fl = f"{floor:.4g} XRP" if floor is not None else "n/a"
        extra = ""
        if owners is not None:
            try:
                extra += f" · {int(owners):,} owners"
            except (TypeError, ValueError):
                pass
        if sales is not None:
            try:
                extra += f" · {int(sales)} sales 24h"
            except (TypeError, ValueError):
                pass
        lines.append(f"  {i}. {name} · floor {fl} · vol {vol} XRP{extra}")
    lines.append(f"  {ATTRIBUTION}")
    return lines


# ---------------------------------------------------------------------------
# Phase 3: whale watch, incoming-offer scan, friend labels.
# Labels are the user's own local notes (favorites file) — never identity
# proof. Every surface carries the attribution credit.
# ---------------------------------------------------------------------------

def _default_labeler():
    """Address -> 'Label (rABC…WXYZ)' from local favorites, or None when
    the favorites store can't be read. Never raises."""
    try:
        import xrpl_common as C
        favs = C.load_favorites()
    except Exception:
        return None
    return lambda a: C.display_address(a, favs)


def _disp(addr, labeler):
    if labeler:
        try:
            return labeler(addr)
        except Exception:
            pass
    if isinstance(addr, str) and len(addr) > 12:
        return f"{addr[:4]}…{addr[-4:]}"
    return addr or "?"


def whale_watch(issuer, currency, limit=10):
    """Top traders by 24h volume for a token. Never raises.

    Returns (token_name, rows|None, note) where note is 'not-found' or
    'unavailable' when rows is None."""
    ccy = (currency or "").upper()
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 10
    try:
        tok = token_lookup(issuer, currency)
        if not tok or not tok.get("md5"):
            return ccy, None, "not-found"
        r = api_get(f"/token/analytics/token/{tok['md5']}/traders",
                    {"limit": limit})
    except Exception:
        return ccy, None, "unavailable"
    traders = (r or {}).get("traders") if isinstance(r, dict) else None
    if not isinstance(traders, list):
        return (tok.get("name") or ccy), None, "unavailable"
    rows = sorted(
        (t for t in traders if isinstance(t, dict)),
        key=lambda t: _xrp_float(t.get("volume24h")) or 0,
        reverse=True)[:limit]
    return (tok.get("name") or ccy), rows, None


def format_whale_watch(issuer, currency, limit=10, labeler=None):
    """Chat/menu-ready whale rows. 24h figures only — all-time
    buy/sell totals are omitted so they can't be misread as 24h flow."""
    name, rows, note = whale_watch(issuer, currency, limit)
    title = f"Whale watch [{name}]:"
    if rows is None:
        if note == "not-found":
            return [title, "  token not found on xrpl.to"]
        return _unavailable_lines(title)
    labeler = labeler or _default_labeler()
    lines = [title]
    if not rows:
        lines.append("  (no trader data)")
    for i, t in enumerate(rows, 1):
        who = _disp(t.get("address"), labeler)
        vol = _fmt_big(_xrp_float(t.get("volume24h")))
        trades = t.get("trades24h")
        pnl = t.get("profit24h")
        try:
            pnl_s = f" · P&L {float(pnl):+,.0f}" if pnl is not None else ""
        except (TypeError, ValueError):
            pnl_s = ""
        lines.append(f"  {i}. {who} · vol {vol}"
                     + (f" · {trades} trades" if trades else "") + pnl_s)
    lines.append("  flow discovery, not advice — volumes are wash-tradable")
    lines.append(f"  {ATTRIBUTION}")
    return lines


def _offer_issuer_scam(nft_id):
    """(flagged: bool|None, issuer|None) for one NFT. Never raises."""
    if not nft_id:
        return None, None
    try:
        nft = nft_detail(nft_id)
        issuer = (nft or {}).get("issuer")
        if not issuer:
            return None, None
        s = scam_check(issuer)
        if not isinstance(s, dict):
            return None, issuer
        return bool(s.get("is_scam")), issuer
    except Exception:
        return None, None


def incoming_offers_report(account, limit=50):
    """Merged incoming NFT offers for an account. Never raises.

    Queries type=buy and type=sell, merges offers/incomingOffers/
    incomingSellOffers, dedupes by offer index, classifies by flags bit 0
    (sell offer). Returns (rows|None, ok): rows is a list of dicts, None
    means the API failed."""
    try:
        limit = max(1, min(int(limit), 50))
    except (TypeError, ValueError):
        limit = 50
    seen, ok = {}, False
    try:
        for typ in ("buy", "sell"):
            r = api_get(f"/nft/account/{account}/offers",
                        {"type": typ, "limit": 50})
            if not isinstance(r, dict):
                continue
            ok = True
            for key in ("offers", "incomingOffers", "incomingSellOffers"):
                for it in r.get(key) or []:
                    if not isinstance(it, dict):
                        continue
                    oid = it.get("index") or it.get("_id")
                    if oid and oid not in seen:
                        seen[oid] = it
    except Exception:
        return None, False
    if not ok:
        return None, False
    rows = []
    for oid, it in seen.items():
        try:
            flags = int(it.get("flags") or 0)
        except (TypeError, ValueError):
            flags = 0
        is_sell = bool(flags & 1)
        amt = it.get("rawAmount", it.get("amount"))
        amount_xrp, amount_s = None, "n/a"
        if isinstance(amt, dict):
            amount_s = (f"{amt.get('value')} {amt.get('currency')}"
                        if amt.get("value") else "n/a")
        else:
            try:
                amount_xrp = float(amt) / 1_000_000
                amount_s = f"{amount_xrp:.4g} XRP"
            except (TypeError, ValueError):
                pass
        try:
            tms = int(it.get("time") or 0)
        except (TypeError, ValueError):
            tms = 0
        rows.append({
            "index": oid,
            "side": "ask" if is_sell else "bid",
            "counterparty": it.get("owner") or it.get("account"),
            "destination": it.get("destination"),
            "nft_id": it.get("NFTokenID"),
            "amount_s": amount_s,
            "amount_xrp": amount_xrp,
            "collection": it.get("collection"),
            "floor_xrp": _xrp_float(it.get("floor")),
            "floor_diff_pct": it.get("floorDiffPct"),
            "fraud": bool(it.get("fraud")),
            "fraud_type": it.get("fraudType"),
            "owner_is_scam": bool(it.get("ownerIsScam")),
            "time_ms": tms,
        })
    rows.sort(key=lambda r: r["time_ms"], reverse=True)
    return rows[:limit], True


def _parse_xrp(v):
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def format_incoming_offers(account, limit=10, hide_flagged=True,
                           collection=None, min_xrp=None, max_xrp=None,
                           from_addr=None, no_safety=False, labeler=None):
    """Chat/menu-ready incoming scan. Counterparties render through the
    labeler ('Jenna X (rABC…WXYZ)'). Flags: xrpl.to's bundled fraud /
    owner-scam flags plus an issuer blocklist screen per displayed row
    (skipped with no_safety). Never raises."""
    title = f"Incoming NFT offers [{account[:8]}…]:"
    rows, ok = incoming_offers_report(account, limit=max(limit * 3, 20))
    if not ok:
        return _unavailable_lines(title)
    labeler = labeler or _default_labeler()
    # resolve a favorite name given as --from
    if from_addr:
        try:
            import xrpl_common as C
            addr, _p = C.resolve_fav_or_addr(from_addr, C.load_favorites())
            if addr:
                from_addr = addr
        except Exception:
            pass
    try:
        import xrpl_common as _C
        _favs = _C.load_favorites()
        known_addrs = {v.get("address") for v in _favs.values()
                       if isinstance(v, dict) and v.get("address")}
    except Exception:
        known_addrs = set()
    min_xrp, max_xrp = _parse_xrp(min_xrp), _parse_xrp(max_xrp)
    hidden = 0
    out = []
    for r in rows:
        if hide_flagged and (r["fraud"] or r["owner_is_scam"]):
            hidden += 1
            continue
        if collection and collection.lower() not in \
                (r["collection"] or "").lower():
            continue
        ax = r["amount_xrp"]
        if min_xrp is not None and ax is not None and ax < min_xrp:
            continue
        if max_xrp is not None and ax is not None and ax > max_xrp:
            continue
        if from_addr and r["counterparty"] != from_addr:
            continue
        out.append(r)
    out = out[:limit]
    # issuer scam screen for the rows we actually display
    screens = {}
    if not no_safety:
        for r in out:
            flagged, _iss = _offer_issuer_scam(r["nft_id"])
            screens[r["index"]] = flagged
    lines = [title]
    if hidden:
        lines.append(f"  ({hidden} offer(s) hidden: flagged by xrpl.to — "
                     "use --include-flagged to show)")
    if not out:
        lines.append("  nothing incoming right now 🎉")
    for i, r in enumerate(out, 1):
        who = _disp(r["counterparty"], labeler)
        nid = r["nft_id"] or "?"
        nid_s = f"{nid[:8]}…{nid[-4:]}" if len(nid) > 14 else nid
        coll = r["collection"] or "untracked collection"
        if r["side"] == "bid":
            head = f"{who} bids {r['amount_s']} on {coll} ({nid_s})"
        else:
            gift = " — GIFT (0 XRP)" if r["amount_xrp"] == 0 else ""
            to_you = " → you" if r["destination"] == account else ""
            head = (f"{who} asks {r['amount_s']} for {coll} "
                    f"({nid_s}){gift}{to_you}")
        lines.append(f"  {i}. {head}")
        sub = []
        if r["floor_xrp"]:
            try:
                fd = float(r["floor_diff_pct"])
                sub.append(f"{fd:+.1f}% vs floor "
                           f"({_fmt_big(r['floor_xrp'])} XRP)")
            except (TypeError, ValueError):
                sub.append(f"floor {_fmt_big(r['floor_xrp'])} XRP")
        if r["fraud"]:
            sub.append(f"⚠️ xrpl.to fraud flag"
                       + (f" ({r['fraud_type']})" if r["fraud_type"] else ""))
        if r["owner_is_scam"]:
            sub.append("⚠️ offer creator flagged as scam")
        flagged = screens.get(r["index"])
        if flagged is True:
            sub.append("🚨 NFT issuer on scam blocklist")
        elif flagged is False:
            sub.append("issuer blocklist: clean ✅")
        if r["side"] == "ask" and r["amount_xrp"] == 0 and \
                r["counterparty"] not in known_addrs:
            sub.append("only accept 0-XRP offers from people you recognize")
        if sub:
            lines.append("     " + " · ".join(sub))
    lines.append("  offers can be cancelled — the ledger is authoritative "
                 "before you act")
    lines.append(f"  {ATTRIBUTION}")
    return lines


# keys create: wallet-signed free API key flow
# ---------------------------------------------------------------------------
#
# Scheme verified against https://xrpl.to/docs/api-keys (2026-09-29):
#   message   = "{address}:{unix_milliseconds}"  (5-min validity window)
#   signature = hex sign of the message's UTF-8 bytes with the wallet key
#               (seed prefix decides: sEd… = ed25519, other s… = secp256k1;
#               xrpl-py's keypairs auto-dispatches)
#   POST /v1/keys with X-Wallet / X-Signature / X-Timestamp / X-Public-Key
#   plus a JSON body describing the project and agreePolicy: true.
#   Response: { "apiKey": "xrpl_…" } — shown once, stored 0600 locally.
# Creating the key accepts xrpl.to's API terms (https://xrpl.to/docs) —
# the operator must know that before approving.

KEY_PROJECT = {
    "name": "xrpl-muse-skill",
    "url": "https://github.com/terramike/xrpl-muse-skill",
    "category": "ai_agent",
    "description": ("Pre-trade scam screening and token risk scoring for "
                    "the XRPL-Muse trading skill (read-only intel)."),
    "expectedDaily": "lt1k",
}

def _wallet_signed_headers(address, seed):
    """The 4 wallet-signature headers for key-management routes.

    Scheme verified against https://xrpl.to/docs/api-keys (2026-09-29):
    message = "{address}:{unix_ms}", hex signature of its UTF-8 bytes.
    """
    from xrpl.core import keypairs
    ts_ms = str(int(time.time() * 1000))
    message = f"{address}:{ts_ms}"
    pub, priv = keypairs.derive_keypair(seed)  # algorithm from seed prefix
    return {
        "X-Wallet": address,
        "X-Signature": keypairs.sign(message.encode("utf-8"), priv),
        "X-Timestamp": ts_ms,
        "X-Public-Key": pub,
    }


def api_signed_get(path, address, seed, timeout=15):
    """GET with wallet-signature headers. Returns (status, dict|None)."""
    req = urllib.request.Request(API_BASE + path,
                                 headers=_headers(_wallet_signed_headers(address, seed)))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, None
    except Exception:
        return 0, None


def api_signed_delete(path, address, seed, timeout=15):
    """DELETE with wallet-signature headers. Returns (status, dict|None)."""
    req = urllib.request.Request(API_BASE + path, method="DELETE",
                                 headers=_headers(_wallet_signed_headers(address, seed)))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"_raw": raw}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, None
    except Exception:
        return 0, None


def keys_list(address, seed):
    """List API keys for a wallet (wallet-signed). Returns (ok, payload)."""
    status, resp = api_signed_get(f"/keys/{address}", address, seed)
    if status == 200 and isinstance(resp, dict):
        return True, resp
    return False, resp


def keys_revoke(address, seed, key_id, yes=False):
    """Revoke (first call) an API key. Requires yes=True."""
    if not yes:
        return False, "refused: pass yes=True (explicit operator approval)"
    status, resp = api_signed_delete(f"/keys/{address}/{key_id}", address, seed)
    if status in (200, 201, 204):
        return True, f"key {key_id} revoked"
    detail = resp.get("error") if isinstance(resp, dict) else resp
    return False, f"revoke failed (http {status}): {detail}"


def keys_create(address, seed, yes=False):
    """Mint a free API key via wallet-signed POST /v1/keys.

    NOT a ledger transaction — nothing is submitted on-chain. The signature
    only proves wallet ownership to the xrpl.to API. Requires yes=True.
    Creating the key accepts xrpl.to's API terms (https://xrpl.to/docs).
    Returns (ok, message). The key itself is stored 0600, never printed.
    """
    if not yes:
        return False, "refused: pass yes=True (explicit operator approval)"
    status, resp = api_post(
        "/keys",
        {"project": KEY_PROJECT, "agreePolicy": True},
        extra_headers=_wallet_signed_headers(address, seed),
    )
    if status in (200, 201) and resp:
        key = resp.get("apiKey") or ""
        if not key and isinstance(resp.get("data"), dict):
            key = resp["data"].get("apiKey") or ""
        if key:
            save_api_key(key)
            return True, (f"API key created and stored at {KEY_PATH} "
                          f"(prefix {key[:8]}…, never displayed in full)")
        return False, f"key created but no apiKey in response: {str(resp)[:200]}"
    detail = ""
    if isinstance(resp, dict):
        detail = resp.get("error") or resp.get("message") or str(resp)[:200]
    return False, f"key creation failed (http {status}): {detail}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def cmd_scam_check(args):
    r = scam_check(args.issuer)
    if r is None:
        print("UNAVAILABLE — could not reach xrpl.to (treat as UNKNOWN)")
        return 1
    print(json.dumps(r, indent=2)[:2000])
    print(ATTRIBUTION)


def cmd_token_risk(args):
    tok = token_lookup(args.issuer, args.currency)
    if not tok:
        print("token not found on xrpl.to (or API unavailable)")
        return 1
    rev = token_review(tok.get("_id"))
    if not rev:
        print("no risk review for this token (or API unavailable)")
        return 1
    print(f"{_risk_emoji(rev.get('score'))} score {rev.get('score')}/10 "
          f"({rev.get('riskLevel')}) — {rev.get('riskCount')} risk / "
          f"{rev.get('positiveCount')} positive")
    print(ATTRIBUTION)


def cmd_safety(args):
    for ln in format_safety_lines(args.issuer, args.currency):
        print(ln)


def cmd_nft_safety(args):
    for ln in format_nft_safety_lines(args.nft_id, args.ask_xrp):
        print(ln)


def cmd_movers(args):
    for ln in format_movers(args.view, args.limit):
        print(ln)


def cmd_token_lookup(args):
    for ln in format_token_lookup(args.issuer, args.currency):
        print(ln)


def cmd_tx_explain(args):
    for ln in format_tx_explain(args.hash):
        print(ln)


def cmd_top_collections(args):
    for ln in format_top_collections(args.sort, args.limit):
        print(ln)


def cmd_whale_watch(args):
    for ln in format_whale_watch(args.issuer, args.currency, args.limit):
        print(ln)


def cmd_incoming_offers(args):
    for ln in format_incoming_offers(
            args.account, limit=args.limit,
            hide_flagged=args.hide_flagged, collection=args.collection,
            min_xrp=args.min_xrp, max_xrp=args.max_xrp,
            from_addr=args.from_addr, no_safety=args.no_safety):
        print(ln)


def cmd_keys(args):
    if args.keys_cmd == "status":
        key = load_api_key()
        if key:
            print(f"API key configured (prefix {key[:8]}…, stored {KEY_PATH})")
        else:
            print("no API key configured — most endpoints work without one; "
                  "run `keys create --yes` to mint a free key")
    elif args.keys_cmd == "create":
        print("This will prove wallet ownership to api.xrpl.to by signing")
        print("a login-style message LOCALLY. Nothing is submitted on-chain,")
        print("no funds move, and the seed never leaves this machine.")
        address = args.address or os.environ.get("XRPL_ADDRESS")
        if not address:
            print("need --address (the wallet the key will be tied to)")
            return 1
        seed = os.environ.get("XRPL_SEED")
        if not seed:
            print("need XRPL_SEED in the environment (same local signer the "
                  "skill already uses — never typed here)")
            return 1
        if not args.yes:
            print(f"message to sign: \"{address}:{int(time.time() * 1000)}\"")
            print("(unix milliseconds; the timestamp refreshes at signing time)")
            print("creating the key accepts xrpl.to's API terms "
                  "(https://xrpl.to/docs)")
            print("re-run with --yes to approve this exact step")
            return 2
        ok, msg = keys_create(address, seed, yes=True)
        print(msg)
        return 0 if ok else 1
    elif args.keys_cmd == "remove":
        print("removed" if remove_api_key() else "no key stored")
    elif args.keys_cmd == "list":
        address, seed = _keys_wallet(args)
        if not address:
            return 1
        ok, resp = keys_list(address, seed)
        if not ok:
            print(f"list failed: {resp}")
            return 1
        keys = (resp or {}).get("keys", []) if isinstance(resp, dict) else []
        if not keys:
            print("no keys on this wallet")
            return 0
        for k in keys:
            print(f"{k.get('id')}  {k.get('keyPrefix')}  {k.get('status')}  "
                  f"{k.get('name', '')}")
        return 0
    elif args.keys_cmd == "revoke":
        address, seed = _keys_wallet(args)
        if not address:
            return 1
        if not args.yes:
            print(f"this revokes key {args.id} on wallet {address} "
                  "(free tier: you can mint a replacement right after)")
            print("re-run with --yes to approve this exact step")
            return 2
        ok, msg = keys_revoke(address, seed, args.id, yes=True)
        print(msg)
        return 0 if ok else 1


def _keys_wallet(args):
    """Resolve (address, seed) for wallet-signed key commands."""
    address = getattr(args, "address", None) or os.environ.get("XRPL_ADDRESS")
    seed = os.environ.get("XRPL_SEED")
    if not address:
        print("need --address (the wallet the key is tied to)")
        return None, None
    if not seed:
        print("need XRPL_SEED in the environment (local signer only)")
        return None, None
    return address, seed


def main(argv=None):
    ap = argparse.ArgumentParser(prog="xrpl_to",
                                 description="xrpl.to API client (read-only intel)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scam-check", help="check an issuer against the scam blocklist")
    p.add_argument("--issuer", required=True)
    p.set_defaults(fn=cmd_scam_check)

    p = sub.add_parser("token-risk", help="risk score for an IOU")
    p.add_argument("--issuer", required=True)
    p.add_argument("--currency", required=True)
    p.set_defaults(fn=cmd_token_risk)

    p = sub.add_parser("safety", help="full safety report lines for a proposal")
    p.add_argument("--issuer", required=True)
    p.add_argument("--currency", required=True)
    p.set_defaults(fn=cmd_safety)

    p = sub.add_parser("nft-safety", help="scam screen + collection floor "
                                          "for an NFT (read-only)")
    p.add_argument("--nft-id", required=True, help="NFTokenID (64 hex chars)")
    p.add_argument("--ask-xrp", default=None,
                   help="asking/bid price in XRP for the floor multiple")
    p.set_defaults(fn=cmd_nft_safety)

    p = sub.add_parser("movers", help="ranked token movers (read-only)")
    p.add_argument("--view", default="gainers",
                   choices=sorted(MOVER_VIEWS),
                   help="gainers|losers|volume|trending (default gainers)")
    p.add_argument("--limit", type=int, default=10, help="rows (max 100)")
    p.set_defaults(fn=cmd_movers)

    p = sub.add_parser("token-lookup", help="token market facts + safety "
                                            "(read-only)")
    p.add_argument("--issuer", required=True)
    p.add_argument("--currency", required=True)
    p.set_defaults(fn=cmd_token_lookup)

    p = sub.add_parser("tx-explain", help="ledger-derived facts for a "
                                          "transaction hash (read-only)")
    p.add_argument("--hash", required=True,
                   help="transaction hash (64 hex chars)")
    p.set_defaults(fn=cmd_tx_explain)

    p = sub.add_parser("top-collections", help="ranked NFT collections "
                                               "(read-only)")
    p.add_argument("--sort", default="vol24h",
                   choices=sorted(TOP_COLLECTION_SORTS),
                   help="ranking (default vol24h)")
    p.add_argument("--limit", type=int, default=10, help="rows (max 200)")
    p.set_defaults(fn=cmd_top_collections)

    p = sub.add_parser("whale-watch", help="top traders by 24h volume "
                                           "for a token (read-only)")
    p.add_argument("--issuer", required=True)
    p.add_argument("--currency", required=True)
    p.add_argument("--limit", type=int, default=10, help="rows (max 50)")
    p.set_defaults(fn=cmd_whale_watch)

    p = sub.add_parser("incoming-offers", help="scan NFT offers incoming "
                       "to an account: bids on its NFTs + offers directed "
                       "at it (read-only)")
    p.add_argument("--account", required=True, help="classic address")
    p.add_argument("--limit", type=int, default=10, help="rows (max 50)")
    p.add_argument("--hide-flagged", dest="hide_flagged",
                   action="store_true", default=True,
                   help="hide xrpl.to-flagged offers (default)")
    p.add_argument("--include-flagged", dest="hide_flagged",
                   action="store_false",
                   help="show flagged offers too")
    p.add_argument("--collection", default=None,
                   help="only offers in this collection (substring)")
    p.add_argument("--min-xrp", default=None, help="min offer price in XRP")
    p.add_argument("--max-xrp", default=None, help="max offer price in XRP")
    p.add_argument("--from", dest="from_addr", default=None,
                   help="only offers from this favorite name or address")
    p.add_argument("--no-safety", action="store_true",
                   help="skip the per-row issuer blocklist screen")
    p.set_defaults(fn=cmd_incoming_offers)

    p = sub.add_parser("keys", help="API key management")
    ks = p.add_subparsers(dest="keys_cmd", required=True)
    q = ks.add_parser("status", help="show whether a key is configured")
    q.set_defaults(fn=cmd_keys)
    q = ks.add_parser("create", help="mint a free API key (wallet-signed, --yes required)")
    q.add_argument("--address", default=None)
    q.add_argument("--yes", action="store_true")
    q.set_defaults(fn=cmd_keys)
    q = ks.add_parser("remove", help="delete the stored key")
    q.set_defaults(fn=cmd_keys)
    q = ks.add_parser("list", help="list keys on a wallet (wallet-signed)")
    q.add_argument("--address", default=None)
    q.set_defaults(fn=cmd_keys)
    q = ks.add_parser("revoke", help="revoke a key by id (wallet-signed, --yes required)")
    q.add_argument("--id", required=True)
    q.add_argument("--address", default=None)
    q.add_argument("--yes", action="store_true")
    q.set_defaults(fn=cmd_keys)

    args = ap.parse_args(argv)
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
