"""xrpl_forensics — read-only light forensic tools for the XRPL skill.

Two commands: `trace` (funding-origin chain: who funded this account,
and who funded them) and `links` (shared counterparties, issuers, and
control overlap between two accounts).

Light by design: every command has a hard RPC-call budget, results are
cached for an hour, and anything unavailable fails open with a NOTE
instead of an error. Nothing here signs, proposes, or needs keys.

Language discipline: output reports on-ledger relationships as LINK:
(facts) and caveats as NOTE:. The word "owner" never appears in output
— a link is not proof of common control.

Spec: references/forensic-mode.md (Phase 1)
"""

import hashlib
import json
import os
import re
import time
from pathlib import Path

import xrpl_eco  # reuse _rpc + RIPPLE_EPOCH

UA = xrpl_eco.UA

# ---------------------------------------------------------------- budgets

TRACE_DEFAULT_DEPTH = 2
TRACE_MAX_DEPTH = 3
LINKS_DEFAULT_WINDOW = 200
LINKS_MAX_WINDOW = 500
CACHE_TTL_SECS = 3600
NFT_OWNER_LOOKUPS_PER_ACCOUNT = 5  # ledger_entry calls, links only
GENESIS_LEDGER = 32570

CACHE_DIR = Path.home() / ".xrpl" / "forensics-cache"

ADDR_RE = re.compile(r"^r[1-9A-HJ-NP-Za-km-z]{25,34}$")

_CALL_COUNT = 0
_NET_FAILED = False


def _bump_calls():
    global _CALL_COUNT
    _CALL_COUNT += 1


def reset_run_state():
    """Reset per-command counters: call budget + network-failure flag."""
    global _CALL_COUNT, _NET_FAILED
    _CALL_COUNT = 0
    _NET_FAILED = False


def call_count():
    return _CALL_COUNT


def net_failed():
    """True if any RPC call has failed during this command's run."""
    return _NET_FAILED


def _rpc(method, params):
    """Rippled RPC via the eco module's server rotation. Counts calls."""
    _bump_calls()
    return xrpl_eco._rpc(method, params)


# ---------------------------------------------------------------- cache

def _cache_dir(explicit=None):
    if explicit is not None:
        return Path(explicit)
    env = os.environ.get("XRPL_FORENSICS_CACHE")
    return Path(env) if env else CACHE_DIR


def _cache_key(method, params):
    raw = json.dumps([method, params], sort_keys=True,
                     separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _cache_get(method, params, cache_dir=None):
    try:
        p = _cache_dir(cache_dir) / (_cache_key(method, params) + ".json")
        rec = json.loads(p.read_text())
        if time.time() - rec.get("ts", 0) <= CACHE_TTL_SECS:
            return rec.get("data")
    except Exception:  # noqa: BLE001 — cache is best-effort
        pass
    return None


def _cache_put(method, params, data, cache_dir=None):
    try:
        d = _cache_dir(cache_dir)
        d.mkdir(parents=True, exist_ok=True)
        p = d / (_cache_key(method, params) + ".json")
        p.write_text(json.dumps({"ts": time.time(), "data": data}))
    except Exception:  # noqa: BLE001 — cache is best-effort
        pass


def rpc_cached(method, params, use_cache=True, cache_dir=None):
    """RPC with 1h local cache. Raises on total failure (caller fails open)."""
    global _NET_FAILED
    if use_cache:
        hit = _cache_get(method, params, cache_dir)
        if hit is not None:
            return hit
    try:
        data = _rpc(method, params)
    except Exception:
        _NET_FAILED = True
        raise
    if use_cache:
        _cache_put(method, params, data, cache_dir)
    return data


# ---------------------------------------------------------------- helpers

def is_address(s):
    return bool(ADDR_RE.match(str(s or "").strip()))


def _fmt_xrp_drops(drops):
    try:
        s = f"{int(drops) / 1_000_000:,.6f}".rstrip("0").rstrip(".")
        return f"{s} XRP"
    except (TypeError, ValueError):
        return "? XRP"


def _fmt_amount(amt):
    if isinstance(amt, dict):
        ccy = xrpl_eco._hex_label(str(amt.get("currency", "?")))
        return f"{amt.get('value', '?')} {ccy}.{amt.get('issuer', '?')[:12]}…"
    return _fmt_xrp_drops(amt)


def _fmt_date(ripple_secs):
    try:
        return time.strftime("%Y-%m-%d",
                             time.gmtime(xrpl_eco.RIPPLE_EPOCH
                                         + int(ripple_secs)))
    except (TypeError, ValueError):
        return "date unknown"


def _ledger_close_time(ledger_index, use_cache=True, cache_dir=None):
    """Close time (Ripple epoch secs) for a ledger index, or None."""
    try:
        res = rpc_cached("ledger", {"ledger_index": ledger_index},
                         use_cache=use_cache, cache_dir=cache_dir)
        return res.get("ledger", {}).get("close_time")
    except Exception:  # noqa: BLE001 — fail-open
        return None


# ---------------------------------------------------------------- trace primitives

def first_tx(account, use_cache=True, cache_dir=None):
    """Oldest validated tx affecting `account`. Dict or None. Never raises."""
    try:
        res = rpc_cached("account_tx",
                         {"account": account, "limit": 1, "forward": True,
                          "ledger_index_min": GENESIS_LEDGER,
                          "ledger_index": "validated"},
                         use_cache=use_cache, cache_dir=cache_dir)
        txs = res.get("transactions", [])
        if txs and isinstance(txs[0], dict) and "tx" in txs[0]:
            return txs[0]["tx"]
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return None


def funding_of(tx, account):
    """Sender address if `tx` funded `account` via inbound Payment.

    Returns None when the birth tx is not an inbound Payment (chain ends
    honestly instead of guessing).
    """
    if not isinstance(tx, dict):
        return None
    if tx.get("TransactionType") != "Payment":
        return None
    if tx.get("Destination") != account:
        return None
    sender = tx.get("Account")
    return sender if sender and sender != account else None


def account_control(account, use_cache=True, cache_dir=None):
    """Control signals: RegularKey?, signer list?, domain? Never raises.

    Returns {"regular_key": bool, "signers": None | {"quorum": int,
    "members": [addr]}, "domain": str | None}.
    """
    out = {"regular_key": False, "signers": None, "domain": None}
    try:
        res = rpc_cached("account_info", {"account": account},
                         use_cache=use_cache, cache_dir=cache_dir)
        data = res.get("account_data", {})
        out["regular_key"] = bool(data.get("RegularKey"))
        out["domain"] = data.get("Domain")
        objs = rpc_cached("account_objects",
                          {"account": account, "limit": 20,
                           "ledger_index": "validated"},
                          use_cache=use_cache, cache_dir=cache_dir)
        for o in objs.get("account_objects", []):
            if isinstance(o, dict) and o.get("LedgerEntryType") \
                    == "SignerList":
                members = [e.get("SignerEntry", {}).get("Account")
                           for e in o.get("SignerEntries", [])
                           if isinstance(e, dict)]
                out["signers"] = {"quorum": o.get("SignerQuorum"),
                                  "members": [m for m in members if m]}
                break
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return out


def _fmt_domain(d):
    """Ledger Domain fields are hex; decode to text for humans."""
    if not d:
        return None
    try:
        return bytes.fromhex(str(d)).decode("ascii", errors="replace")
    except (ValueError, TypeError):
        return str(d)


def _fmt_control(ctrl):
    bits = []
    bits.append("RegularKey set" if ctrl["regular_key"]
                else "no RegularKey")
    if ctrl["signers"]:
        q = ctrl["signers"]["quorum"]
        n = len(ctrl["signers"]["members"])
        bits.append(f"signer list (quorum {q} of {n})")
    else:
        bits.append("no signer list")
    dom = _fmt_domain(ctrl.get("domain"))
    if dom:
        bits.append(f"domain {dom}")
    return " · ".join(bits)


def format_trace(address, depth=TRACE_DEFAULT_DEPTH, use_cache=True,
                 cache_dir=None):
    """Funding-origin trace. Returns chat-ready lines. Never raises."""
    reset_run_state()
    lines = []
    try:
        return _format_trace_inner(address, depth, use_cache, cache_dir,
                                   lines)
    except Exception:  # noqa: BLE001 — fail-open
        lines.append("  ⚠️  trace unavailable (network error) — "
                     "try again later.")
        return lines


def _format_trace_inner(address, depth, use_cache, cache_dir, lines):
    if not is_address(address):
        return ["  ⚠️  not a valid XRPL classic address."]
    depth = max(1, min(int(depth), TRACE_MAX_DEPTH))
    budget = (depth + 1) * 4  # first_tx + account_info + account_objects + ledger
    lines.append(f"TRACE {address} (light mode: ≤{budget} RPC calls)")
    seen = set()
    cur = address
    for hop in range(depth + 1):
        tx = first_tx(cur, use_cache=use_cache, cache_dir=cache_dir)
        hop_net_ok = not net_failed()
        if tx is None:
            if hop_net_ok:
                lines.append(f"  Hop {hop}  {cur}: no on-ledger history "
                             f"(unfunded or unknown account)")
            else:
                lines.append("  ⚠️  trace unavailable (network error) — "
                             "try again later.")
            break
        ledger_index = tx.get("ledger_index")
        close = _ledger_close_time(ledger_index, use_cache=use_cache,
                                   cache_dir=cache_dir)
        ctrl = account_control(cur, use_cache=use_cache,
                               cache_dir=cache_dir)
        ctrl_unknown = net_failed() and hop_net_ok
        tx_hash = tx.get("hash", "")
        lines.append(f"  Hop {hop}  {cur}")
        lines.append(f"    first seen: ledger {ledger_index} "
                     f"({_fmt_date(close)})")
        funder = funding_of(tx, cur)
        if funder:
            amt = tx.get("Amount")
            if isinstance(tx.get("meta"), dict):
                amt = tx["meta"].get("delivered_amount", amt)
            lines.append(f"    funded by: {funder} — {_fmt_amount(amt)} "
                         f"(tx {str(tx_hash)[:16]}…)")
        else:
            lines.append(f"    birth tx: {tx.get('TransactionType')} "
                         f"(tx {str(tx_hash)[:16]}…) — not an inbound "
                         f"Payment, chain ends here")
        if ctrl_unknown:
            lines.append("    control: unknown (network error)")
        else:
            lines.append(f"    control: {_fmt_control(ctrl)}")
        if not funder or funder in seen:
            break
        seen.add(cur)
        cur = funder
    lines.append(f"  used {call_count()} of ≤{budget} RPC calls")
    if net_failed():
        lines.append("  ⚠️  network errors during trace — chain may be "
                     "incomplete; treat as partial.")
    lines.append("LINK: funding chain shown above (money flow, hop by hop)")
    lines.append("NOTE: funding links show where XRP came from, not who "
                 "controls the account. A link is not proof of common "
                 "control.")
    return lines


# ---------------------------------------------------------------- links primitives

def recent_txs(account, window, use_cache=True, cache_dir=None):
    """Most-recent validated txs for `account`, up to `window`. Never raises."""
    txs = []
    try:
        remaining = max(1, min(int(window), LINKS_MAX_WINDOW))
        marker = None
        while remaining > 0:
            params = {"account": account,
                      "limit": min(remaining, 200),
                      "ledger_index": "validated"}
            if marker:
                params["marker"] = marker
            res = rpc_cached("account_tx", params, use_cache=use_cache,
                             cache_dir=cache_dir)
            batch = [t["tx"] for t in res.get("transactions", [])
                     if isinstance(t, dict) and "tx" in t]
            txs.extend(batch)
            marker = res.get("marker")
            remaining -= len(batch)
            if not marker or not batch:
                break
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return txs


def extract_counterparties(tx, me):
    """Pure: counterparties + NFT offer indexes + DEX flag from one tx.

    Returns (counterparties: set, nft_offer_indexes: list, dex: bool).
    Never raises.
    """
    cps, offers, dex = set(), [], False
    try:
        if not isinstance(tx, dict):
            return cps, offers, dex
        tt = tx.get("TransactionType")
        acct, dest = tx.get("Account"), tx.get("Destination")
        if tt == "Payment":
            if acct == me and dest and dest != me:
                cps.add(dest)
            elif dest == me and acct and acct != me:
                cps.add(acct)
        elif tt == "TrustSet":
            lim = tx.get("LimitAmount")
            issuer = lim.get("issuer") if isinstance(lim, dict) else None
            if acct == me and issuer and issuer != me:
                cps.add(issuer)
            elif issuer == me and acct and acct != me:
                cps.add(acct)
        elif tt in ("EscrowCreate", "PaymentChannelCreate"):
            if acct == me and dest and dest != me:
                cps.add(dest)
            elif dest == me and acct and acct != me:
                cps.add(acct)
        elif tt == "EscrowFinish":
            owner = tx.get("Owner")
            if acct == me and owner and owner != me:
                cps.add(owner)
            elif owner == me and acct and acct != me:
                cps.add(acct)
        elif tt == "NFTokenAcceptOffer":
            for k in ("NFTokenSellOffer", "NFTokenBuyOffer"):
                if tx.get(k):
                    offers.append(tx[k])
        elif tt == "OfferCreate":
            dex = True
    except Exception:  # noqa: BLE001 — pure but defensive
        pass
    return cps, offers, dex


def nft_offer_seller(offer_index, use_cache=True, cache_dir=None):
    """Current holder address of an NFTokenOffer, or None. Never raises."""
    try:
        res = rpc_cached("ledger_entry",
                         {"index": offer_index,
                          "ledger_index": "validated"},
                         use_cache=use_cache, cache_dir=cache_dir)
        node = res.get("node", {})
        if node.get("LedgerEntryType") == "NFTokenOffer":
            return node.get("Account")
    except Exception:  # noqa: BLE001 — fail-open (offer gone)
        pass
    return None


def account_issuers(account, use_cache=True, cache_dir=None):
    """Trustline issuer set for `account`. Never raises."""
    out = set()
    try:
        res = rpc_cached("account_lines",
                         {"account": account, "limit": 400,
                          "ledger_index": "validated"},
                         use_cache=use_cache, cache_dir=cache_dir)
        for line in res.get("lines", []):
            if isinstance(line, dict) and line.get("account"):
                out.add(line["account"])
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return out


def _collect_side(account, window, use_cache, cache_dir):
    """Counterparty multiset + DEX count + issuers for one account."""
    counts = {}
    dex_n = 0
    lookups = 0
    for tx in recent_txs(account, window, use_cache=use_cache,
                         cache_dir=cache_dir):
        cps, offers, dex = extract_counterparties(tx, account)
        for cp in cps:
            counts[cp] = counts.get(cp, 0) + 1
        if dex:
            dex_n += 1
        for oi in offers:
            if lookups >= NFT_OWNER_LOOKUPS_PER_ACCOUNT:
                break
            holder = nft_offer_seller(oi, use_cache=use_cache,
                                      cache_dir=cache_dir)
            lookups += 1
            if holder and holder != account:
                counts[holder] = counts.get(holder, 0) + 1
    return counts, dex_n


def format_links(addr_a, addr_b, window=LINKS_DEFAULT_WINDOW,
                 use_cache=True, cache_dir=None):
    """Shared counterparties/issuers/control between two accounts.

    Returns chat-ready lines. Never raises.
    """
    reset_run_state()
    lines = []
    try:
        return _format_links_inner(addr_a, addr_b, window, use_cache,
                                   cache_dir, lines)
    except Exception:  # noqa: BLE001 — fail-open
        lines.append("  ⚠️  links unavailable (network error) — "
                     "try again later.")
        return lines


def _format_links_inner(addr_a, addr_b, window, use_cache, cache_dir,
                        lines):
    if not is_address(addr_a) or not is_address(addr_b):
        return ["  ⚠️  both arguments must be valid XRPL classic addresses."]
    if addr_a == addr_b:
        return ["  ⚠️  give two different addresses."]
    window = max(1, min(int(window), LINKS_MAX_WINDOW))
    lines.append(f"LINKS {addr_a} ↔ {addr_b}")
    lines.append(f"  window: {window} most recent validated txs per account")

    counts_a, dex_a = _collect_side(addr_a, window, use_cache, cache_dir)
    counts_b, dex_b = _collect_side(addr_b, window, use_cache, cache_dir)

    # --- control overlap (strongest signal first)
    ctrl_a = account_control(addr_a, use_cache=use_cache,
                             cache_dir=cache_dir)
    ctrl_b = account_control(addr_b, use_cache=use_cache,
                             cache_dir=cache_dir)
    lines.append("  Control overlap:")
    found = False
    rk_a = ctrl_a["regular_key"] and _regular_key_of(addr_a, use_cache,
                                                    cache_dir)
    rk_b = ctrl_b["regular_key"] and _regular_key_of(addr_b, use_cache,
                                                    cache_dir)
    if rk_a and rk_b and rk_a == rk_b:
        lines.append(f"    LINK: same RegularKey {rk_a} on both accounts")
        found = True
    mem_a = set((ctrl_a["signers"] or {}).get("members", []))
    mem_b = set((ctrl_b["signers"] or {}).get("members", []))
    shared_mem = sorted(mem_a & mem_b)
    if shared_mem:
        lines.append(f"    LINK: {len(shared_mem)} shared signer-list "
                     f"member(s): {', '.join(shared_mem)}")
        found = True
    if not found:
        lines.append("    (none — different RegularKeys / signer lists)")

    # --- shared counterparties
    shared = sorted(set(counts_a) & set(counts_b),
                    key=lambda c: -(counts_a[c] + counts_b[c]))
    lines.append(f"  Shared counterparties ({len(shared)}):")
    for cp in shared[:20]:
        lines.append(f"    LINK: {cp} — A: {counts_a[cp]} txs, "
                     f"B: {counts_b[cp]} txs")
    if len(shared) > 20:
        lines.append(f"    …and {len(shared) - 20} more")
    if not shared:
        lines.append("    (none in window)")
    lines.append("  NOTE: a shared counterparty can be an exchange hot "
                 "wallet or public service — a shared counterparty is a "
                 "link, not proof of common control.")

    # --- shared issuers
    iss_a = account_issuers(addr_a, use_cache=use_cache,
                            cache_dir=cache_dir)
    iss_b = account_issuers(addr_b, use_cache=use_cache,
                            cache_dir=cache_dir)
    shared_iss = sorted(iss_a & iss_b)
    lines.append(f"  Shared trustline issuers ({len(shared_iss)}):")
    for iss in shared_iss[:20]:
        lines.append(f"    LINK: {iss}")
    if not shared_iss:
        lines.append("    (none)")

    # --- DEX activity (no counterparty claims in light mode)
    lines.append(f"  DEX activity in window: A placed {dex_a} offer(s) · "
                 f"B placed {dex_b} offer(s) (light mode makes no "
                 f"counterparty claims for DEX fills)")

    lines.append(f"  used {call_count()} RPC calls (cached where possible)")
    if net_failed():
        lines.append("  ⚠️  network errors during reads — treat empty "
                     "sections as UNKNOWN, not empty; results are partial.")
    lines.append("NOTE: window covers recent history only — older activity "
                 "is out of scope for light mode. Links are on-ledger "
                 "relationships, not ownership.")
    return lines


def _regular_key_of(account, use_cache=True, cache_dir=None):
    """The RegularKey address itself, or None. Never raises."""
    try:
        res = rpc_cached("account_info", {"account": account},
                         use_cache=use_cache, cache_dir=cache_dir)
        return res.get("account_data", {}).get("RegularKey")
    except Exception:  # noqa: BLE001 — fail-open
        return None
