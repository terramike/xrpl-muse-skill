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

SEEN_PATH = Path.home() / ".xrpl" / "hidden_files" / "validators-seen.json"


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
    if rep["ledger"]:
        lines.append(f"  ledger {rep['ledger']}; 80% supermajority held "
                     "2 weeks activates an amendment.")
    return lines


# ---------------------------------------------------------------- XRPL Meta

def xrplmeta_lookup(currency, issuer):
    """Single token record from XRPL Meta. Returns dict or None. Never raises."""
    try:
        ccy = currency_to_hex(currency)
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
