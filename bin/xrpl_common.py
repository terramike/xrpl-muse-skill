#!/usr/bin/env python3
"""xrpl_common: shared pure helpers for xrpl-trade (proposer) and xrpl-sign.

No network, no seeds here — just parsing, encoding, hashing, and summaries.
"""
import hashlib
import json
import os
import sys
import time
from decimal import Decimal, InvalidOperation, ROUND_DOWN
from pathlib import Path

XRPL_DIR = Path.home() / ".xrpl"
CONFIG_PATH = XRPL_DIR / "config.json"
APPROVED_PATH = XRPL_DIR / "approved.json"
POLICY_PATH = XRPL_DIR / "policy.json"
PROPOSALS_DIR = XRPL_DIR / "proposals"
STATE_PATH = XRPL_DIR / "state.json"
AUDIT_PATH = XRPL_DIR / "audit.log"

NETWORKS = {
    "mainnet": ["https://s1.ripple.com:51234", "https://s2.ripple.com:51234"],
    "testnet": ["https://s.altnet.rippletest.net:51234"],
    "devnet": ["https://s.devnet.rippletest.net:51234"],
}
RIPPLE_EPOCH = 946684800  # unix seconds of 2000-01-01T00:00:00Z

__version__ = "0.2.0"


def _sanitize_proxy_env():
    for var in ("no_proxy", "NO_PROXY"):
        val = os.environ.get(var)
        if val:
            os.environ[var] = ",".join(
                p for p in val.split(",") if "[" not in p and "]" not in p)


_sanitize_proxy_env()


# ---------- amounts / currencies ----------

def dec(s, name):
    try:
        d = Decimal(str(s))
    except (InvalidOperation, ValueError):
        sys.exit(f"Bad {name}: {s!r}")
    if d <= 0:
        sys.exit(f"{name} must be positive.")
    return d


def currency_code(code: str) -> str:
    """3-char codes pass through; longer ones hex160-encode (grid-wizard style)."""
    code = code.upper()
    if len(code) == 3 and code.isascii() and code.isalnum():
        return code
    raw = code.encode("ascii")
    if len(raw) > 20:
        sys.exit(f"currency code too long: {code!r}")
    return (raw + b"\x00" * (20 - len(raw))).hex().upper()


def display_currency(code: str) -> str:
    if isinstance(code, str) and len(code) == 40:
        try:
            raw = bytes.fromhex(code).rstrip(b"\x00")
            if raw.isascii():
                return raw.decode()
        except ValueError:
            pass
    return code


def norm_token(currency: str, issuer):
    """Canonical (CURRENCY, issuer-or-None) with XRP native."""
    c = display_currency(currency).upper()
    if c == "XRP":
        return ("XRP", None)
    return (c, issuer)


def load_approved():
    try:
        return json.loads(APPROVED_PATH.read_text()).get("pairs", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def approved_token_set():
    """Set of (CURRENCY, issuer) allowed by the allowlist. XRP always allowed."""
    toks = {("XRP", None)}
    for p in load_approved().values():
        toks.add(norm_token(p["base"], p.get("base_issuer")))
        toks.add(norm_token(p["quote"], p.get("quote_issuer")))
    return toks


def resolve_pair(args):
    """Return (base, base_issuer, quote, quote_issuer)."""
    if getattr(args, "pair", None):
        name = args.pair.upper()
        pairs = load_approved()
        if name not in pairs:
            known = ", ".join(sorted(pairs)) or "none"
            sys.exit(f"unknown pair {name!r}. Approved: {known} (see {APPROVED_PATH})")
        p = pairs[name]
        return p["base"].upper(), p.get("base_issuer"), p["quote"].upper(), p.get("quote_issuer")
    base = args.base.upper()
    quote = args.quote.upper()
    return base, getattr(args, "base_issuer", None), quote, getattr(args, "quote_issuer", None)


# ---------- hashing / proposals ----------

def canonical_hash(tx_dict: dict) -> str:
    blob = json.dumps(tx_dict, sort_keys=True, separators=(",", ":"),
                      default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def ripple_time_from_now(seconds: int) -> int:
    return int(time.time()) - RIPPLE_EPOCH + seconds


def save_proposal(tx_dict, network, account, action, summary_lines, extra=None):
    h = canonical_hash(tx_dict)
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    proposal = {
        "proposal_hash": h,
        "created_at": int(time.time()),
        "network": network,
        "account": account,
        "action": action,
        "summary": summary_lines,
        "tx": tx_dict,
        "meta": extra or {},
    }
    (PROPOSALS_DIR / f"{h}.json").write_text(json.dumps(proposal, indent=2, default=str))
    return h, proposal


def load_proposal(prefix: str):
    matches = list(PROPOSALS_DIR.glob(f"{prefix}*.json")) if PROPOSALS_DIR.exists() else []
    if not matches:
        sys.exit(f"No proposal matching {prefix!r}. See `xrpl-sign --list`.")
    if len(matches) > 1:
        sys.exit(f"Ambiguous prefix {prefix!r}: {[m.stem[:12] for m in matches]}")
    return json.loads(matches[0].read_text()), matches[0]


# ---------- policy / state ----------

DEFAULT_POLICY = {
    "network_lock": "testnet",
    "max_fee_drops": 1000,
    "per_tx_max_xrp": 25,
    "daily_max_xrp": 100,
    "destination_allowlist": [],
    "max_deviation_bps": 1000,
    "proposal_ttl_seconds": 86400,
}


def load_policy():
    if not POLICY_PATH.exists():
        sys.exit(f"No policy file. Run `xrpl-sign init-policy` first ({POLICY_PATH}).")
    try:
        pol = json.loads(POLICY_PATH.read_text())
    except json.JSONDecodeError:
        sys.exit(f"Policy file is not valid JSON: {POLICY_PATH}")
    merged = dict(DEFAULT_POLICY)
    merged.update(pol)
    return merged


def load_state():
    try:
        st = json.loads(STATE_PATH.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        st = {}
    today = time.strftime("%Y-%m-%d", time.gmtime())
    if st.get("date") != today:
        st = {"date": today, "spent_xrp": "0"}
    return st


def save_state(st):
    XRPL_DIR.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(json.dumps(st))


def audit(action, proposal_hash, tx_hash, network, account, result, note=""):
    XRPL_DIR.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": int(time.time()),
        "action": action,
        "proposal_hash": proposal_hash,
        "tx_hash": tx_hash,
        "network": network,
        "account": account,
        "result": result,
        "note": note,
    }
    with AUDIT_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


# ---------- network client (lazy: imports xrpl-py only when called) ----------

def make_client(network):
    import asyncio
    import time as _time
    from xrpl.clients import JsonRpcClient
    from xrpl.models.requests import ServerInfo

    def _request(self, request):
        return asyncio.run(self._request_impl(request, timeout=30.0))

    last_err = None
    for url in NETWORKS[network]:
        c = JsonRpcClient(url)
        c.request = _request.__get__(c, JsonRpcClient)
        for attempt in range(3):
            try:
                if c.request(ServerInfo()).is_successful():
                    return c
                break
            except Exception as e:  # noqa: BLE001
                last_err = e
                _time.sleep(1 + attempt)
    sys.exit(f"No healthy {network} node ({last_err}).")


# ---------- tx introspection (used by the signer on raw tx JSON) ----------

def tx_tokens(tx):
    """All non-XRP (currency, issuer) identities touched by a tx, from the
    tx JSON itself — not from CLI args, so raw-issuer bypass is impossible."""
    toks = set()

    def add_amount(a):
        if isinstance(a, dict):
            toks.add(norm_token(a["currency"], a.get("issuer")))

    ttype = tx.get("TransactionType")
    if ttype == "OfferCreate":
        add_amount(tx.get("TakerPays"))
        add_amount(tx.get("TakerGets"))
    elif ttype == "TrustSet":
        add_amount(tx.get("LimitAmount"))
    elif ttype == "Payment":
        add_amount(tx.get("Amount"))
    toks.discard(("XRP", None))
    return toks


def tx_xrp_at_risk(tx):
    """XRP value at risk for caps: the XRP side of an offer/payment, else 0."""
    from xrpl.utils import drops_to_xrp

    def as_xrp(a):
        if isinstance(a, str):  # drops
            return Decimal(drops_to_xrp(a))
        return None

    ttype = tx.get("TransactionType")
    if ttype == "OfferCreate":
        return as_xrp(tx.get("TakerPays")) or as_xrp(tx.get("TakerGets")) or Decimal(0)
    if ttype == "Payment":
        return as_xrp(tx.get("Amount")) or Decimal(0)
    return Decimal(0)


def tx_fee_xrp(tx):
    from xrpl.utils import drops_to_xrp
    return Decimal(drops_to_xrp(tx.get("Fee", "0")))
