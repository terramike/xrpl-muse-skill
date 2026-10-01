"""xrpl_forensics — read-only light forensic tools for the XRPL skill.

Phase 1: `trace` (funding-origin chain: who funded this account, and who
funded them) and `links` (shared counterparties, issuers, and control
overlap between two accounts).
Phase 2: `flow` (top counterparties by volume in/out), `nft-trail`
(NFT mint → transfer/sale provenance), `token-trail` (issuer profile,
holder spread, token flow), a token section inside `links`, and a
known-address label registry (`LABEL:` lines) that marks exchange /
service wallets so plumbing stops looking like conspiracy.

Light by design: every command has a hard RPC-call budget, results are
cached for an hour, and anything unavailable fails open with a NOTE
instead of an error. Nothing here signs, proposes, or needs keys.

Language discipline: output reports on-ledger relationships as LINK:
(facts), registry labels as LABEL:, and caveats as NOTE:. The word
"owner" never appears in output — a link is not proof of common
control; NFTs are "held by" an account.

Spec: references/forensic-mode.md (Phase 1 + Phase 2)
"""

import hashlib
import json
import os
import re
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

import xrpl_eco  # reuse _rpc + RIPPLE_EPOCH

UA = xrpl_eco.UA

# ---------------------------------------------------------------- budgets

TRACE_DEFAULT_DEPTH = 2
TRACE_MAX_DEPTH = 3
LINKS_DEFAULT_WINDOW = 200
LINKS_MAX_WINDOW = 500
FLOW_DEFAULT_WINDOW = 200
FLOW_MAX_WINDOW = 500
TOKEN_TRAIL_DEFAULT_WINDOW = 200
TOKEN_TRAIL_MAX_WINDOW = 500
NFT_HISTORY_PAGE_LIMIT = 20
NFT_HISTORY_MAX_PAGES = 5
NFT_OFFER_RESOLVE_CAP = 10   # ledger_entry calls while walking an NFT chain
TOKEN_ISSUER_INFO_CAP = 3    # account_info calls enriching links tokens
TOKEN_HOLDER_PAGES = 2       # account_lines pages scanned for holder spread
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


def rpc_cached(method, params, use_cache=True, cache_dir=None,
               quiet=False):
    """RPC with 1h local cache. Raises on total failure (caller fails open).

    quiet=True: don't trip the run's network-failure flag — for lookups
    that are *expected* to miss (e.g. consumed NFT offers).
    """
    global _NET_FAILED
    if use_cache:
        hit = _cache_get(method, params, cache_dir)
        if hit is not None:
            return hit
    try:
        data = _rpc(method, params)
    except Exception:
        if not quiet:
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

def _normalize_entry(entry):
    """Tx dict with sibling metadata merged in. Never raises.

    Live account_tx/nft_history entries carry `meta` *beside* `tx`,
    not inside it; downstream parsing (delivered amounts, DEX fills)
    expects it inside. Returns a new dict; the response is untouched.
    """
    try:
        if not isinstance(entry, dict):
            return {}
        src = entry.get("tx")
        if not isinstance(src, dict):
            # bare-tx response shape: the entry itself is the tx
            src = entry if isinstance(entry.get("TransactionType"),
                                      str) else {}
        tx = dict(src)
        meta = entry.get("meta")
        if isinstance(meta, dict) and not isinstance(tx.get("meta"),
                                                     dict):
            tx["meta"] = meta
        return tx
    except Exception:  # noqa: BLE001 — defensive
        return {}


def _validated_ledger_index(use_cache=True, cache_dir=None):
    """Pin the current validated ledger index for history queries.

    History scans must bound their range explicitly: a bare
    ``ledger_index: "validated"`` on account_tx selects ONE ledger, not
    history. Returns int or None (caller fails open).
    """
    try:
        res = rpc_cached("ledger", {"ledger_index": "validated"},
                         use_cache=use_cache, cache_dir=cache_dir)
        return int(res.get("ledger_index", 0)) or None
    except Exception:  # noqa: BLE001 — fail-open
        return None


def first_tx(account, use_cache=True, cache_dir=None):
    """Oldest validated tx affecting `account`. Dict or None. Never raises."""
    try:
        hi = _validated_ledger_index(use_cache, cache_dir)
        if not hi:
            return None
        res = rpc_cached("account_tx",
                         {"account": account, "limit": 1, "forward": True,
                          "ledger_index_min": GENESIS_LEDGER,
                          "ledger_index_max": hi},
                         use_cache=use_cache, cache_dir=cache_dir)
        txs = res.get("transactions", [])
        if txs and isinstance(txs[0], dict) and "tx" in txs[0]:
            return _normalize_entry(txs[0])
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

    Returns {"regular_key": address | None, "signers": None | {"quorum": int,
    "members": [addr]}, "domain": str | None}.
    """
    out = {"regular_key": None, "signers": None, "domain": None}
    try:
        res = rpc_cached("account_info", {"account": account},
                         use_cache=use_cache, cache_dir=cache_dir)
        data = res.get("account_data", {})
        out["regular_key"] = data.get("RegularKey")  # address or None
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
    chain_addrs = [address]
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
        lines.append(f"  Hop {hop}  {fmt_labeled(cur)}")
        lines.append(f"    first seen: ledger {ledger_index} "
                     f"({_fmt_date(close)})")
        funder = funding_of(tx, cur)
        if funder:
            amt = tx.get("Amount")
            if isinstance(tx.get("meta"), dict):
                amt = tx["meta"].get("delivered_amount", amt)
            lines.append(f"    funded by: {fmt_labeled(funder)} — "
                         f"{_fmt_amount(amt)} "
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
        chain_addrs.append(funder)
        cur = funder
    lines.append(f"  used {call_count()} of ≤{budget} RPC calls")
    if net_failed():
        lines.append("  ⚠️  network errors during trace — chain may be "
                     "incomplete; treat as partial.")
    if any_labeled(chain_addrs):
        lines.append("  " + LABELS_NOTE)
    lines.append("LINK: funding chain shown above (money flow, hop by hop)")
    lines.append("NOTE: funding links show where XRP came from, not who "
                 "controls the account. A link is not proof of common "
                 "control.")
    return lines


# ---------------------------------------------------------------- links primitives

def recent_txs(account, window, use_cache=True, cache_dir=None):
    """Most-recent validated txs for `account`, up to `window`. Never raises.

    Records the serving node's reported history range in _LAST_TX_RANGE
    so formatters can distinguish "account is quiet" from "node is
    blind".
    """
    global _LAST_TX_RANGE
    txs = []
    try:
        # Pin the upper bound once: every page scans real history
        # (newest-first) instead of a single "validated" ledger.
        hi = _validated_ledger_index(use_cache, cache_dir)
        if not hi:
            return []
        remaining = max(1, min(int(window), LINKS_MAX_WINDOW))
        marker = None
        first_page = True
        while remaining > 0:
            params = {"account": account,
                      "limit": min(remaining, 200),
                      "ledger_index_max": hi}
            if marker:
                params["marker"] = marker
            res = rpc_cached("account_tx", params, use_cache=use_cache,
                             cache_dir=cache_dir)
            if first_page:
                _LAST_TX_RANGE = (res.get("ledger_index_min"),
                                  res.get("ledger_index_max"))
                first_page = False
            batch = [_normalize_entry(t)
                     for t in res.get("transactions", [])]
            batch = [t for t in batch if t]
            txs.extend(batch)
            marker = res.get("marker")
            remaining -= len(batch)
            if not marker or not batch:
                break
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return txs


_LAST_TX_RANGE = None

# A node reporting fewer ledgers than this is treated as history-thin:
# an empty window on such a node may mean blindness, not quiet.
THIN_HISTORY_LEDGERS = 100_000


def _history_note():
    """NOTE warning about a history-thin serving node, or "".

    Only fires when the node reported a thin history range — a
    full-history node with a quiet account gets no note. Never raises.
    """
    try:
        lo, hi = _LAST_TX_RANGE or (None, None)
        if lo and hi and int(hi) - int(lo) < THIN_HISTORY_LEDGERS:
            return (f"NOTE: the serving node only reported history for "
                    f"ledgers {int(lo):,}–{int(hi):,}; an empty window "
                    f"can mean the node can't see older activity, not "
                    f"that the account is quiet.")
    except Exception:  # noqa: BLE001 — defensive
        pass
    return ""


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
                         use_cache=use_cache, cache_dir=cache_dir,
                         quiet=True)  # consumed offers are gone: not an error
        node = res.get("node", {})
        if node.get("LedgerEntryType") == "NFTokenOffer":
            return node.get("Account")
    except Exception:  # noqa: BLE001 — fail-open (offer gone)
        pass
    return None


def account_token_lines(account, use_cache=True, cache_dir=None):
    """(currency, issuer) pairs from `account`'s trustlines. Currency may
    be None for malformed lines. Never raises."""
    out = []
    try:
        res = rpc_cached("account_lines",
                         {"account": account, "limit": 400,
                          "ledger_index": "validated"},
                         use_cache=use_cache, cache_dir=cache_dir)
        for line in res.get("lines", []):
            if isinstance(line, dict) and line.get("account"):
                ccy = line.get("currency")
                out.append((str(ccy) if ccy else None, line["account"]))
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return out


def account_issuers(account, use_cache=True, cache_dir=None):
    """Trustline issuer set for `account`. Never raises."""
    return {iss for _, iss in account_token_lines(
        account, use_cache=use_cache, cache_dir=cache_dir)}


def account_tokens(account, window_txs, use_cache=True, cache_dir=None):
    """Token touch map for `account`: {(currency, issuer): {"txs": n,
    "held": bool}}. Trustlines + TrustSet/Payment touches in `window_txs`.
    Never raises."""
    touches = {}
    try:
        for ccy, iss in account_token_lines(account, use_cache=use_cache,
                                            cache_dir=cache_dir):
            if ccy:
                touches.setdefault((ccy, iss),
                                   {"txs": 0, "held": True})
        for tx in window_txs:
            if not isinstance(tx, dict):
                continue
            tt = tx.get("TransactionType")
            if tt == "TrustSet":
                lim = tx.get("LimitAmount")
                if isinstance(lim, dict) and lim.get("currency") \
                        and lim.get("issuer"):
                    key = (str(lim["currency"]), lim["issuer"])
                    touches.setdefault(key, {"txs": 0, "held": False})
                    touches[key]["txs"] += 1
            elif tt == "Payment":
                meta = tx.get("meta") \
                    if isinstance(tx.get("meta"), dict) else {}
                amt = meta.get("delivered_amount", tx.get("Amount"))
                if isinstance(amt, dict) and amt.get("currency") \
                        and amt.get("issuer"):
                    key = (str(amt["currency"]), amt["issuer"])
                    touches.setdefault(key, {"txs": 0, "held": False})
                    touches[key]["txs"] += 1
    except Exception:  # noqa: BLE001 — defensive
        pass
    return touches


def _collect_side(account, window, use_cache, cache_dir):
    """Counterparty multiset + DEX count + tx list for one account."""
    counts = {}
    dex_n = 0
    lookups = 0
    txs = recent_txs(account, window, use_cache=use_cache,
                     cache_dir=cache_dir)
    for tx in txs:
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
    return counts, dex_n, txs


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

    counts_a, dex_a, txs_a = _collect_side(addr_a, window, use_cache,
                                           cache_dir)
    counts_b, dex_b, txs_b = _collect_side(addr_b, window, use_cache,
                                           cache_dir)

    # --- control overlap (strongest signal first)
    ctrl_a = account_control(addr_a, use_cache=use_cache,
                             cache_dir=cache_dir)
    ctrl_b = account_control(addr_b, use_cache=use_cache,
                             cache_dir=cache_dir)
    lines.append("  Control overlap:")
    found = False
    rk_a, rk_b = ctrl_a["regular_key"], ctrl_b["regular_key"]
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
        na, nb = counts_a[cp], counts_b[cp]
        lines.append(f"    LINK: {cp} — A: {na} tx{'s' if na != 1 else ''}, "
                     f"B: {nb} tx{'s' if nb != 1 else ''}")
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

    # --- shared tokens (Phase 2)
    toks_a = account_tokens(addr_a, txs_a, use_cache=use_cache,
                            cache_dir=cache_dir)
    toks_b = account_tokens(addr_b, txs_b, use_cache=use_cache,
                            cache_dir=cache_dir)
    shared_toks = sorted(set(toks_a) & set(toks_b),
                         key=lambda k: -(toks_a[k]["txs"]
                                         + toks_b[k]["txs"]))
    lines.append(f"  Shared tokens ({len(shared_toks)}):")
    enriched = 0
    for ccy, iss in shared_toks[:20]:
        ta, tb = toks_a[(ccy, iss)], toks_b[(ccy, iss)]
        iss_disp = fmt_labeled(iss) if label_of(iss) \
            else f"{iss[:12]}…"
        disp = f"{xrpl_eco._hex_label(ccy)}.{iss_disp}"
        flags_s = ""
        if enriched < TOKEN_ISSUER_INFO_CAP:
            prof = issuer_profile(iss, use_cache=use_cache,
                                  cache_dir=cache_dir)
            enriched += 1
            if not prof["unknown"]:
                bits = []
                if prof["transfer_fee_pct"]:
                    fee_s = (f"{prof['transfer_fee_pct']:.3f}"
                             .rstrip("0").rstrip("."))
                    bits.append(f"fee {fee_s}%")
                if prof["global_freeze"]:
                    bits.append("GLOBAL FREEZE")
                flags_s = (" · " + ", ".join(bits)) if bits else ""
            else:
                flags_s = " · issuer info unknown"
        ta_n, tb_n = ta["txs"], tb["txs"]
        lines.append(f"    LINK: {disp} — A: {ta_n} tx"
                     f"{'s' if ta_n != 1 else ''}, "
                     f"B: {tb_n} tx{'s' if tb_n != 1 else ''}"
                     f"{flags_s}")
    if not shared_toks:
        lines.append("    (none)")
    lines.append("  NOTE: holding or touching the same token is a weak "
                 "link — widely held tokens (stablecoins etc.) connect "
                 "millions of unrelated accounts.")

    # --- DEX activity (no counterparty claims in light mode)
    lines.append(f"  DEX activity in window: A placed {dex_a} offer(s) · "
                 f"B placed {dex_b} offer(s) (light mode makes no "
                 f"counterparty claims for DEX fills)")
    if not txs_a and not txs_b:
        note = _history_note()
        if note:
            lines.append("  " + note)

    lines.append(f"  used {call_count()} RPC calls (cached where possible)")
    if net_failed():
        lines.append("  ⚠️  network errors during reads — treat empty "
                     "sections as UNKNOWN, not empty; results are partial.")
    if any_labeled([addr_a, addr_b] + shared + shared_iss
                   + [iss for _, iss in shared_toks]):
        lines.append("  " + LABELS_NOTE)
    lines.append("NOTE: window covers recent history only — older activity "
                 "is out of scope for light mode. Links are on-ledger "
                 "relationships, not ownership.")
    return lines


# ---------------------------------------------------------------- labels (Phase 2)

LABELS_SCHEMA_VERSION = 1


def _labels_paths():
    """(shipped candidates, user override). Never raises."""
    here = Path(__file__).resolve().parent
    shipped = [here / "references" / "known-labels.json",      # skill-mirror layout
               here.parent / "references" / "known-labels.json"]  # repo layout
    user = Path.home() / ".xrpl" / "labels.local.json"
    return shipped, user


_labels_cache = None


def load_labels():
    """Merged label map {address: entry}. User-local wins. Never raises."""
    global _labels_cache
    if _labels_cache is not None:
        return _labels_cache
    merged = {}
    shipped, user = _labels_paths()
    for p in shipped + [user]:
        try:
            data = json.loads(p.read_text())
            for e in data.get("labels", []):
                a = e.get("address")
                if a and is_address(a):
                    merged[a] = e
        except Exception:  # noqa: BLE001 — missing/unreadable file is fine
            pass
    _labels_cache = merged
    return merged


def reset_labels_cache():
    """For tests."""
    global _labels_cache
    _labels_cache = None


def label_of(address):
    """Registry entry for `address`, or None. Never raises."""
    try:
        return load_labels().get(address)
    except Exception:  # noqa: BLE001 — defensive
        return None


def fmt_labeled(address):
    """Address with its registry label, or the bare address. Never raises.

    Approved Phase 2 rendering: LABEL: rXXX… — "Name" (verified),
    printed inline wherever a labeled address appears.
    """
    e = label_of(address)
    if not e:
        return address
    ver = e.get("verification", "unverified")
    return f'LABEL: {address} — "{e.get("label", "?")}" ({ver})'


def any_labeled(addresses):
    """True if any address in the iterable has a label. Never raises."""
    try:
        return any(label_of(a) for a in addresses)
    except Exception:  # noqa: BLE001 — defensive
        return False


LABELS_NOTE = ("NOTE: links through labeled service wallets are usually "
               "plumbing, not relationships — a shared exchange wallet is "
               "a link, not proof of common control.")


# ---------------------------------------------------------------- amounts (Phase 2)

def _parse_amount(amt):
    """(ccy_key, Decimal) for an XRPL amount. (None, None) if unparsable.

    ccy_key is "XRP" or "<raw_currency>.<issuer>". Never raises.
    """
    try:
        if isinstance(amt, dict):
            ccy = str(amt.get("currency", ""))
            issuer = str(amt.get("issuer", ""))
            if not ccy or not issuer:
                return None, None
            return f"{ccy}.{issuer}", Decimal(str(amt.get("value", "0")))
        return "XRP", Decimal(int(amt)) / Decimal(1_000_000)
    except (InvalidOperation, ValueError, TypeError, AttributeError):
        return None, None


def _amt_sub(a, b):
    """(ccy_key, a - b) for two same-currency amounts. (None, None) else."""
    ka, da = _parse_amount(a)
    kb, db = _parse_amount(b)
    if ka and ka == kb:
        return ka, da - db
    return None, None


def _disp_ccy(ccy_key):
    """Human display for a ccy_key: XRP or CODE.issuer-prefix."""
    if ccy_key == "XRP":
        return "XRP"
    ccy, _, issuer = ccy_key.partition(".")
    return f"{xrpl_eco._hex_label(ccy)}.{issuer[:12]}…"


def _fmt_vol(ccy_key, dec):
    try:
        q = f"{dec:,.4f}".rstrip("0").rstrip(".")
        return f"{q} {_disp_ccy(ccy_key)}"
    except Exception:  # noqa: BLE001 — defensive
        return f"? {_disp_ccy(ccy_key)}"


def _dex_fills(tx, me):
    """Executed fills inside an OfferCreate tx.

    Returns [(counterparty, my_in, my_out)] where my_in/my_out are
    [(ccy_key, Decimal)] from MY perspective: I received my_in from the
    counterparty and paid my_out to them. Never raises.
    """
    fills = []
    try:
        meta = tx.get("meta")
        if not isinstance(meta, dict):
            return fills
        for wrap in meta.get("AffectedNodes", []):
            if not isinstance(wrap, dict):
                continue
            node = wrap.get("ModifiedNode") or wrap.get("DeletedNode")
            if not isinstance(node, dict):
                continue
            if node.get("LedgerEntryType") != "Offer":
                continue
            fin = node.get("FinalFields") or {}
            cp = fin.get("Account")
            if not cp or cp == me:
                continue
            prev = node.get("PreviousFields")
            if isinstance(prev, dict):
                gets_c = _amt_sub(prev.get("TakerGets"), fin.get("TakerGets"))
                pays_c = _amt_sub(prev.get("TakerPays"), fin.get("TakerPays"))
            else:
                # DeletedNode without PreviousFields: offer fully consumed
                gets_c = _parse_amount(fin.get("TakerGets"))
                pays_c = _parse_amount(fin.get("TakerPays"))
            my_in, my_out = [], []
            # TakerGets is what the TAKER gets: the consumed amount of
            # the maker's TakerGets flowed to me (my_in); consumed
            # TakerPays is what I paid the maker (my_out).
            if gets_c[0] and gets_c[1] > 0:
                my_in.append(gets_c)
            if pays_c[0] and pays_c[1] > 0:
                my_out.append(pays_c)
            if my_in or my_out:
                fills.append((cp, my_in, my_out))
    except Exception:  # noqa: BLE001 — defensive
        pass
    return fills


def tx_value_flows(tx, me):
    """Value movement in one tx, from `me`'s perspective.

    Returns {counterparty: {"in": {ccy: Decimal}, "out": {ccy: Decimal},
    "txs": int}}. Only tesSUCCESS transactions count; Payments use ONLY
    the delivered amount (never the requested Amount); OfferCreates use
    executed fills from AffectedNodes. Failed txs and txs with missing
    metadata contribute nothing — unavailable evidence is unknown, not
    movement. NFT and non-value txs contribute nothing. Never raises.
    """
    flows = {}

    def credit(cp, side, ccy, dec):
        """Record volume; True if recorded. Zero amounts are noise: skipped."""
        if not dec:
            return False
        e = flows.setdefault(cp, {"in": {}, "out": {}, "txs": 0})
        e[side][ccy] = e[side].get(ccy, Decimal(0)) + dec
        return True

    def touch(cp):
        flows[cp]["txs"] += 1

    try:
        if not isinstance(tx, dict):
            return flows
        tt = tx.get("TransactionType")
        acct, dest = tx.get("Account"), tx.get("Destination")
        meta = tx.get("meta") if isinstance(tx.get("meta"), dict) else {}
        # Only successful transactions MOVE value. A failed Payment
        # (tecPATH_DRY, tecUNFUNDED_OFFER, ...) changes nothing except
        # the fee — counting its requested Amount would fabricate flows.
        if meta.get("TransactionResult") != "tesSUCCESS":
            return flows
        if tt == "Payment":
            # The delivered amount is the ONLY honest measure of a
            # Payment's movement. Never fall back to the requested
            # Amount: on a partial payment or missing metadata that
            # would overstate what moved. Absent evidence is reported
            # as unknown (no flow), not guessed.
            ccy, dec = _parse_amount(meta.get("delivered_amount"))
            if not ccy or dec is None:
                return flows
            if acct == me and dest and dest != me:
                if credit(dest, "out", ccy, dec):
                    touch(dest)
            elif dest == me and acct and acct != me:
                if credit(acct, "in", ccy, dec):
                    touch(acct)
        elif tt == "OfferCreate" and acct == me:
            for cp, my_in, my_out in _dex_fills(tx, me):
                moved = False
                for ccy, dec in my_in:
                    moved |= credit(cp, "in", ccy, dec)
                for ccy, dec in my_out:
                    moved |= credit(cp, "out", ccy, dec)
                if moved:
                    touch(cp)
    except Exception:  # noqa: BLE001 — defensive
        pass
    return flows


def _xrp_vol(entry):
    return entry["in"].get("XRP", Decimal(0)) \
        + entry["out"].get("XRP", Decimal(0))


def _fmt_vols(vol_map, limit=3):
    """'1,250 XRP · 300 USD.rABC…' for the top `limit` currencies."""
    ranked = sorted(vol_map.items(), key=lambda kv: -kv[1])[:limit]
    return " · ".join(_fmt_vol(k, d) for k, d in ranked) or "—"


def format_flow(address, window=FLOW_DEFAULT_WINDOW, use_cache=True,
                cache_dir=None):
    """Top counterparties by volume in/out. Returns chat lines. Never raises."""
    reset_run_state()
    lines = []
    try:
        return _format_flow_inner(address, window, use_cache, cache_dir,
                                  lines)
    except Exception:  # noqa: BLE001 — fail-open
        lines.append("  ⚠️  flow unavailable (network error) — "
                     "try again later.")
        return lines


def _format_flow_inner(address, window, use_cache, cache_dir, lines):
    if not is_address(address):
        return ["  ⚠️  not a valid XRPL classic address."]
    window = max(1, min(int(window), FLOW_MAX_WINDOW))
    budget = (window + 199) // 200 + 1  # tx pages + headroom
    lines.append(f"FLOW {address} (light mode: window {window}, "
                 f"≤{budget} RPC calls)")

    agg = {}
    for tx in recent_txs(address, window, use_cache=use_cache,
                         cache_dir=cache_dir):
        for cp, e in tx_value_flows(tx, address).items():
            a = agg.setdefault(cp, {"in": {}, "out": {}, "txs": 0})
            for side in ("in", "out"):
                for ccy, dec in e[side].items():
                    a[side][ccy] = a[side].get(ccy, Decimal(0)) + dec
            a["txs"] += e["txs"]

    for side, verb in (("in", "received"), ("out", "sent")):
        ranked = sorted(
            ((cp, e) for cp, e in agg.items() if e[side]),
            key=lambda kv: (-_xrp_vol(kv[1]), -kv[1]["txs"]))[:10]
        lines.append(f"  {verb.upper()} (top {len(ranked)}, "
                     f"ranked by XRP volume):")
        for cp, e in ranked:
            n = e["txs"]
            lines.append(f"    LINK: {fmt_labeled(cp)} — {verb} "
                         f"{_fmt_vols(e[side])} · {n} tx"
                         f"{'s' if n != 1 else ''}")
        if not ranked:
            lines.append("    (none in window)")

    lines.append(f"  used {call_count()} RPC calls (cached where possible)")
    if net_failed():
        lines.append("  ⚠️  network errors during reads — treat empty "
                     "sections as UNKNOWN, not empty; results are partial.")
    if any_labeled(agg):
        lines.append("  " + LABELS_NOTE)
    if not agg:
        note = _history_note()
        if note:
            lines.append("  " + note)
    lines.append("NOTE: ranked by XRP volume; IOU volumes are shown per row "
                 "with units unconverted. Volumes are wash-tradable — flow "
                 "is discovery, not proof of economic substance. Window "
                 "covers recent history only.")
    return lines


# ---------------------------------------------------------------- nft-trail (Phase 2)

# XRP Ledger base58 dialect (leading zero byte -> 'r', hence classic
# addresses start with r). NOT the Bitcoin alphabet.
_B58 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def _b58check_encode(payload20):
    """Classic address for 20 payload bytes (version 0x00). Never raises."""
    import hashlib as _hl
    raw = b"\x00" + bytes(payload20)
    chk = _hl.sha256(_hl.sha256(raw).digest()).digest()[:4]
    num = int.from_bytes(raw + chk, "big")
    out = ""
    while num > 0:
        num, rem = divmod(num, 58)
        out = _B58[rem] + out
    n_pad = 0
    for b in raw + chk:
        if b == 0:
            n_pad += 1
        else:
            break
    return _B58[0] * n_pad + out


def nft_issuer_of(token_id):
    """Issuer classic address decoded from an NFTokenID, or None."""
    try:
        raw = bytes.fromhex(token_id[8:48])
        addr = _b58check_encode(raw)
        return addr if is_address(addr) else None
    except Exception:  # noqa: BLE001 — defensive
        return None


def _nft_id_valid(tid):
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", str(tid or "").strip()))


def nft_offer_detail(offer_index, use_cache=True, cache_dir=None):
    """(owner_address, amount) for an NFTokenOffer index. (None, None) if
    the offer is gone or unreadable. Never raises."""
    try:
        res = rpc_cached("ledger_entry",
                         {"index": offer_index,
                          "ledger_index": "validated"},
                         use_cache=use_cache, cache_dir=cache_dir,
                         quiet=True)  # settled offers are gone: not an error
        node = res.get("node", {})
        if node.get("LedgerEntryType") == "NFTokenOffer":
            return node.get("Account"), node.get("Amount")
    except Exception:  # noqa: BLE001 — fail-open (offer gone)
        pass
    return None, None


def nft_open_offers(token_id, use_cache=True, cache_dir=None):
    """(sell_count, buy_count) of open offers for a token. Never raises."""
    sell = buy = 0
    try:
        for method in ("nft_sell_offers", "nft_buy_offers"):
            # a token with no open offers has no offer directory:
            # objectNotFound is an expected miss, not an error
            res = rpc_cached(method,
                             {"nft_id": token_id,
                              "ledger_index": "validated"},
                             use_cache=use_cache, cache_dir=cache_dir,
                             quiet=True)
            offers = res.get("offers", [])
            if method == "nft_sell_offers":
                sell = len(offers)
            else:
                buy = len(offers)
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return sell, buy


def format_nft_trail(token_id, use_cache=True, cache_dir=None):
    """NFT provenance: mint → transfers/sales → current holder.

    Returns chat-ready lines. Never raises.
    """
    reset_run_state()
    lines = []
    try:
        return _format_nft_trail_inner(token_id, use_cache, cache_dir,
                                       lines)
    except Exception:  # noqa: BLE001 — fail-open
        lines.append("  ⚠️  nft-trail unavailable (network error) — "
                     "try again later.")
        return lines


def _format_nft_trail_inner(token_id, use_cache, cache_dir, lines):
    token_id = str(token_id or "").strip()
    if not _nft_id_valid(token_id):
        return ["  ⚠️  not a valid NFTokenID (64 hex characters)."]
    lines.append(f"NFT-TRAIL {token_id[:16]}… (light mode: nft_history, "
                 f"≤{NFT_HISTORY_MAX_PAGES + NFT_OFFER_RESOLVE_CAP + 2} "
                 f"RPC calls)")

    history = None
    try:
        history = []
        marker = None
        for _ in range(NFT_HISTORY_MAX_PAGES):
            params = {"nft_id": token_id, "ledger_index": "validated",
                      "limit": NFT_HISTORY_PAGE_LIMIT}
            if marker:
                params["marker"] = marker
            res = rpc_cached("nft_history", params, use_cache=use_cache,
                             cache_dir=cache_dir)
            batch = res.get("transactions", [])
            history.extend(batch)
            marker = res.get("marker")
            if not marker or not batch:
                break
    except Exception:  # noqa: BLE001 — fall back to issuer scan
        history = None

    if history is None:
        return _nft_trail_fallback(token_id, use_cache, cache_dir, lines)

    txs = []
    for entry in history:
        tx = _normalize_entry(entry) if isinstance(entry, dict) else {}
        if tx:
            txs.append(tx)
    txs.reverse()  # nft_history is newest-first; show chronological

    holder = None
    minted = False
    resolves = 0
    hops = 0
    for tx in txs:
        tt = tx.get("TransactionType")
        acct = tx.get("Account")
        ledger = tx.get("ledger_index")
        date = _fmt_date(tx.get("date"))
        h = str(tx.get("hash", ""))[:16]
        if tt == "NFTokenMint":
            holder = acct
            minted = True
            hops += 1
            lines.append(f"  Hop {hops}  minted by {fmt_labeled(acct)} — "
                         f"ledger {ledger} ({date}) (tx {h}…)")
            lines.append(f"    LINK: {token_id[:16]}… minted by {acct}")
        elif tt == "NFTokenCreateOffer":
            sell = bool((tx.get("Flags") or 0) & 1)
            amt = _fmt_amount(tx.get("Amount"))
            dest = tx.get("Destination")
            side = "sell" if sell else "buy"
            extra = f" → {fmt_labeled(dest)}" if dest else ""
            lines.append(f"  offer: {side} {amt} by {fmt_labeled(acct)}"
                         f"{extra} — ledger {ledger} ({date})")
        elif tt == "NFTokenAcceptOffer":
            sell_idx = tx.get("NFTokenSellOffer")
            buy_idx = tx.get("NFTokenBuyOffer")
            idx = sell_idx or buy_idx
            owner, amount = (None, None)
            if idx and resolves < NFT_OFFER_RESOLVE_CAP:
                owner, amount = nft_offer_detail(
                    idx, use_cache=use_cache, cache_dir=cache_dir)
                resolves += 1
            price = _fmt_amount(amount) if amount else "price unknown"
            if sell_idx:
                # accepter buys from the offer owner
                buyer, seller = acct, owner
                holder = buyer
            else:
                # accepter sells into the offer owner's bid
                buyer, seller = owner, acct
                holder = buyer
            hops += 1
            if seller and buyer:
                lines.append(
                    f"  Hop {hops}  sold {fmt_labeled(seller)} → "
                    f"{fmt_labeled(buyer)} for {price} — ledger {ledger} "
                    f"({date}) (tx {h}…)")
                lines.append(f"    LINK: transfer {seller} → {buyer} "
                             f"({price})")
            else:
                # Settled offers are deleted on acceptance, so their
                # detail is usually unrecoverable — the offer line(s)
                # printed above carry the terms when they were created.
                lines.append(f"  Hop {hops}  accepted by "
                             f"{fmt_labeled(acct)} — ledger {ledger} "
                             f"({date}) (settled offer detail unavailable; "
                             f"see offer lines above)")
        elif tt == "NFTokenCancelOffer":
            lines.append(f"  offer cancelled by {fmt_labeled(acct)} — "
                         f"ledger {ledger} ({date})")
        elif tt == "NFTokenBurn":
            lines.append(f"  burned by {fmt_labeled(acct)} — ledger "
                         f"{ledger} ({date})")
            holder = None

    if not minted and not txs:
        lines.append("  (no on-ledger history found for this token)")
    if holder:
        lines.append(f"  currently held by {fmt_labeled(holder)} "
                     f"(derived from the last on-ledger transfer)")
    sell_n, buy_n = nft_open_offers(token_id, use_cache=use_cache,
                                    cache_dir=cache_dir)
    lines.append(f"  open offers now: {sell_n} sell / {buy_n} buy")
    lines.append(f"  used {call_count()} RPC calls (cached where possible)")
    if net_failed():
        lines.append("  ⚠️  network errors during reads — chain may be "
                     "incomplete; treat as partial.")
    if any_labeled([t.get("Account") for t in txs
                    if isinstance(t, dict)]):
        lines.append("  " + LABELS_NOTE)
    lines.append("NOTE: on-ledger chain only — off-ledger (OTC) deals are "
                 "invisible. Transfers show holder movement, not identity.")
    return lines


def _mint_matches(tx, token_id):
    """True if this NFTokenMint tx created `token_id`, per metadata.

    Mint txs carry no NFTokenID field — the token ID only appears in
    the minter's NFTokenPage node. Never raises.
    """
    try:
        meta = tx.get("meta") or {}
        if not isinstance(meta, dict):
            return False
        for wrap in meta.get("AffectedNodes", []):
            if not isinstance(wrap, dict):
                continue
            node = wrap.get("CreatedNode") or wrap.get("ModifiedNode")
            if not isinstance(node, dict):
                continue
            if node.get("LedgerEntryType") != "NFTokenPage":
                continue
            fields = node.get("NewFields") or node.get("FinalFields") \
                or {}
            toks = fields.get("NFTokens") or []
            for nft in toks:
                if not isinstance(nft, dict):
                    continue
                tok = nft.get("NFToken") or {}
                if str(tok.get("NFTokenID", "")).lower() \
                        == token_id.lower():
                    return True
    except Exception:  # noqa: BLE001 — defensive
        pass
    return False


def _nft_trail_fallback(token_id, use_cache, cache_dir, lines):
    """Bounded issuer scan when nft_history is unavailable. Never raises."""
    issuer = nft_issuer_of(token_id)
    if not issuer:
        lines.append("  ⚠️  nft_history unavailable on this node and the "
                     "issuer could not be decoded — try again later.")
        return lines
    found = None
    try:
        # Scan real history (oldest-first from genesis) for the mint —
        # a single "validated" ledger would only ever see yesterday.
        hi = _validated_ledger_index(use_cache, cache_dir)
        if not hi:
            return lines
        marker = None
        for _ in range(NFT_HISTORY_MAX_PAGES):
            params = {"account": issuer, "limit": 100, "forward": True,
                      "ledger_index_min": GENESIS_LEDGER,
                      "ledger_index_max": hi}
            if marker:
                params["marker"] = marker
            res = rpc_cached("account_tx", params, use_cache=use_cache,
                             cache_dir=cache_dir)
            for entry in res.get("transactions", []):
                tx = _normalize_entry(entry)
                if tx.get("TransactionType") == "NFTokenMint" \
                        and _mint_matches(tx, token_id):
                    found = tx
                    break
            if found:
                break
            marker = res.get("marker")
            if not marker:
                break
    except Exception:  # noqa: BLE001 — fail-open
        pass
    if found:
        ledger = found.get("ledger_index")
        date = _fmt_date(found.get("date"))
        lines.append(f"  minted by {fmt_labeled(found.get('Account'))} — "
                     f"ledger {ledger} ({date})")
        lines.append(f"    LINK: {token_id[:16]}… minted by "
                     f"{found.get('Account')}")
    else:
        lines.append("  (mint tx not found in the scanned issuer history)")
    lines.append("NOTE: nft_history is unavailable on this node — only the "
                 "mint hop is shown. Re-run against a full-history node "
                 "for the complete chain.")
    return lines


# ---------------------------------------------------------------- token-trail (Phase 2)

LSF_GLOBAL_FREEZE = 0x00400000
LSF_NO_FREEZE = 0x00200000
LSF_DEFAULT_RIPPLE = 0x00800000


def issuer_profile(issuer, use_cache=True, cache_dir=None):
    """Issuer legitimacy signals. Never raises.

    Returns {"domain", "transfer_fee_pct", "global_freeze", "no_freeze",
    "default_ripple", "tick_size", "unknown"}.
    """
    out = {"domain": None, "transfer_fee_pct": 0.0, "global_freeze": False,
           "no_freeze": False, "default_ripple": False, "tick_size": None,
           "unknown": True}
    try:
        res = rpc_cached("account_info", {"account": issuer},
                         use_cache=use_cache, cache_dir=cache_dir)
        d = res.get("account_data", {})
        if not d:
            return out
        out["unknown"] = False
        out["domain"] = _fmt_domain(d.get("Domain"))
        try:
            tr = int(d.get("TransferRate", 1000000000))
            out["transfer_fee_pct"] = (tr - 1_000_000_000) / 10_000_000
        except (TypeError, ValueError):
            pass
        try:
            flags = int(d.get("Flags", 0))
        except (TypeError, ValueError):
            flags = 0
        out["global_freeze"] = bool(flags & LSF_GLOBAL_FREEZE)
        out["no_freeze"] = bool(flags & LSF_NO_FREEZE)
        out["default_ripple"] = bool(flags & LSF_DEFAULT_RIPPLE)
        out["tick_size"] = d.get("TickSize")
    except Exception:  # noqa: BLE001 — fail-open
        pass
    return out


def _fmt_issuer_flags(prof):
    bits = []
    fee = prof["transfer_fee_pct"]
    fee_s = f"{fee:.3f}".rstrip("0").rstrip(".")
    bits.append(f"transfer fee {fee_s}%" if fee else "transfer fee 0%")
    bits.append("GLOBAL FREEZE on" if prof["global_freeze"]
                else "no global freeze")
    bits.append("no-freeze set" if prof["no_freeze"] else "freeze possible")
    if prof["tick_size"]:
        bits.append(f"tick size {prof['tick_size']}")
    if prof["domain"]:
        bits.append(f"domain {prof['domain']}")
    return " · ".join(bits)


def token_holders(issuer, currency, use_cache=True, cache_dir=None):
    """Top holders from a bounded account_lines scan.

    Returns (holders, scanned): holders = [(address, Decimal(balance))]
    top 10; scanned = number of trustlines read. The scan is explicitly
    partial. Never raises.
    """
    holders = []
    scanned = 0
    try:
        marker = None
        for _ in range(TOKEN_HOLDER_PAGES):
            params = {"account": issuer, "limit": 400,
                      "ledger_index": "validated"}
            if marker:
                params["marker"] = marker
            res = rpc_cached("account_lines", params, use_cache=use_cache,
                             cache_dir=cache_dir)
            for line in res.get("lines", []):
                if not isinstance(line, dict):
                    continue
                if str(line.get("currency", "")) != currency:
                    continue
                scanned += 1
                try:
                    bal = abs(Decimal(str(line.get("balance", "0"))))
                except (InvalidOperation, ValueError):
                    continue
                if bal > 0:
                    holders.append((line.get("account"), bal))
            marker = res.get("marker")
            if not marker:
                break
    except Exception:  # noqa: BLE001 — fail-open
        pass
    holders.sort(key=lambda h: -h[1])
    return holders[:10], scanned


def _normalize_currency(ccy):
    """Ledger-form currency from user input, or None.

    Accepts 3-letter codes ("USD"), 40-char hex, and short ASCII
    names ("RLUSD" → its ledger hex form). Returned uppercase;
    _hex_label() renders it back for display.
    """
    c = str(ccy or "").strip()
    if not c or not c.isascii():
        return None
    if re.fullmatch(r"[0-9a-fA-F]{40}", c):
        return c.upper()
    if re.fullmatch(r"[A-Za-z0-9]{3}", c):
        return c.upper()
    if 3 < len(c) <= 20 and re.fullmatch(r"[A-Za-z0-9]+", c):
        return c.encode("ascii").hex().ljust(40, "0").upper()
    return None


def format_token_trail(issuer, currency, window=TOKEN_TRAIL_DEFAULT_WINDOW,
                       use_cache=True, cache_dir=None):
    """Issuer profile + holder spread + recent token flow.

    Returns chat-ready lines. Never raises.
    """
    reset_run_state()
    lines = []
    try:
        return _format_token_trail_inner(issuer, currency, window,
                                         use_cache, cache_dir, lines)
    except Exception:  # noqa: BLE001 — fail-open
        lines.append("  ⚠️  token-trail unavailable (network error) — "
                     "try again later.")
        return lines


def _format_token_trail_inner(issuer, currency, window, use_cache,
                              cache_dir, lines):
    if not is_address(issuer):
        return ["  ⚠️  not a valid issuer address."]
    currency = _normalize_currency(currency)
    if not currency:
        return ["  ⚠️  currency must be a 3-letter code, a short name "
                "like RLUSD, or 40-char hex."]
    window = max(1, min(int(window), TOKEN_TRAIL_MAX_WINDOW))
    disp = xrpl_eco._hex_label(currency)
    lines.append(f"TOKEN-TRAIL {disp}.{issuer[:12]}… (light mode: window "
                 f"{window}, ≤{2 + TOKEN_HOLDER_PAGES + (window + 199) // 200 + 1} "
                 f"RPC calls)")

    # --- issuer profile
    prof = issuer_profile(issuer, use_cache=use_cache,
                          cache_dir=cache_dir)
    lines.append("  Issuer:")
    if prof["unknown"]:
        lines.append("    (issuer account data unavailable)")
    else:
        lines.append(f"    LINK: issuer {fmt_labeled(issuer)} — "
                     f"{_fmt_issuer_flags(prof)}")

    # --- holder spread (bounded, explicitly partial)
    holders, scanned = token_holders(issuer, currency, use_cache=use_cache,
                                     cache_dir=cache_dir)
    lines.append(f"  Top holders (first {scanned:,} trustlines "
                 f"scanned — partial, not the full distribution):")
    for addr, bal in holders:
        lines.append(f"    LINK: {fmt_labeled(addr)} — "
                     f"{_fmt_vol(f'{currency}.{issuer}', bal)}")
    if not holders:
        lines.append("    (none found in scanned trustlines)")

    # --- recent flow in this token
    vols = {}
    for tx in recent_txs(issuer, window, use_cache=use_cache,
                         cache_dir=cache_dir):
        if not isinstance(tx, dict) or tx.get("TransactionType") \
                != "Payment":
            continue
        meta = tx.get("meta") if isinstance(tx.get("meta"), dict) else {}
        amt = meta.get("delivered_amount", tx.get("Amount"))
        if not isinstance(amt, dict):
            continue
        if str(amt.get("currency", "")) != currency:
            continue
        ccy, dec = _parse_amount(amt)
        if not ccy or dec is None:
            continue
        for party in (tx.get("Account"), tx.get("Destination")):
            if party and party != issuer:
                e = vols.setdefault(party, {"vol": Decimal(0), "txs": 0})
                e["vol"] += dec
                e["txs"] += 1
    ranked = sorted(vols.items(), key=lambda kv: (-kv[1]["vol"],
                                                 -kv[1]["txs"]))[:10]
    lines.append(f"  Movers (top {len(ranked)} addresses by {disp} volume, "
                 f"in+out — issuer-involved flow only):")
    for addr, e in ranked:
        n = e["txs"]
        lines.append(f"    LINK: {fmt_labeled(addr)} — moved "
                     f"{_fmt_vol(f'{currency}.{issuer}', e['vol'])} · "
                     f"{n} tx{'s' if n != 1 else ''}")
    if not ranked:
        lines.append("    (no token payments in window)")
        note = _history_note()
        if note:
            lines.append("  " + note)

    lines.append(f"  used {call_count()} RPC calls (cached where possible)")
    if net_failed():
        lines.append("  ⚠️  network errors during reads — treat empty "
                     "sections as UNKNOWN, not empty; results are partial.")
    if label_of(issuer) or any_labeled([a for a, _ in holders]
                                       + [a for a, _ in ranked]):
        lines.append("  " + LABELS_NOTE)
    lines.append("NOTE: holder list is a bounded partial scan — concentration "
                 "claims need the full trustline set. Issuer flags are "
                 "current state and can change. Volumes are wash-tradable. "
                 "Movers cover only issuer-involved flow (issuance, "
                 "redemption, rippling through the issuer) — ordinary "
                 "holder-to-holder transfers don't touch the issuer account "
                 "and are invisible to this scan.")
    return lines
