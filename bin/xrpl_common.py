#!/usr/bin/env python3
"""xrpl_common v0.3: shared helpers for xrpl-trade (proposer) and xrpl-sign.

No network, no seeds here — parsing, encoding, hashing, summaries, policy
loading, and the concurrency-safe spend tracker.

v0.3 hardening (see SECURITY.md):
  - Proposals are hash-bound ENVELOPES (format/network/account/action/
    created_at/policy_version/tx_binary). The signer verifies the envelope
    and DERIVES every safety-critical value from the transaction itself —
    stored summaries/metadata are never trusted.
  - Strict transaction-type allowlist + per-type field schemas.
  - Per-asset spend limits and exact-pair allowlist enforcement.
  - Atomic daily-limit reservation (crash/race safe).
"""
import contextlib
import fcntl
import hashlib
import json
import os
import sys
import time
from decimal import Decimal, InvalidOperation
from pathlib import Path

XRPL_DIR = Path.home() / ".xrpl"
CONFIG_PATH = XRPL_DIR / "config.json"          # address+network only (proposer)
APPROVED_PATH = XRPL_DIR / "approved.json"
POLICY_PATH = XRPL_DIR / "policy.json"
PROPOSALS_DIR = XRPL_DIR / "proposals"
STATE_PATH = XRPL_DIR / "state.json"
STATE_LOCK_PATH = XRPL_DIR / "state.lock"
AUDIT_PATH = XRPL_DIR / "audit.log"

NETWORKS = {
    "mainnet": ["https://s1.ripple.com:51234", "https://s2.ripple.com:51234"],
    "testnet": ["https://s.altnet.rippletest.net:51234"],
    "devnet": ["https://s.devnet.rippletest.net:51234"],
}
RIPPLE_EPOCH = 946684800  # unix seconds of 2000-01-01T00:00:00Z
REQUIRE_DEST_TAG_FLAG = 0x00020000  # lsfRequireDestTag

__version__ = "0.3.0"
POLICY_VERSION = 3
ENVELOPE_FORMAT = "xrpl-proposal/3"
# Fields covered by the proposal hash. Everything safety-critical lives here.
# Notably: network, creation time, policy version, and the canonical binary
# transaction. Summaries are NOT stored and NOT trusted — the signer derives
# them from the transaction.
ENVELOPE_HASH_KEYS = ("format", "network", "account", "action",
                      "created_at", "policy_version", "tx_binary")


def _sanitize_proxy_env():
    for var in ("no_proxy", "NO_PROXY"):
        val = os.environ.get(var)
        if val:
            os.environ[var] = ",".join(
                p for p in val.split(",") if "[" not in p and "]" not in p)


_sanitize_proxy_env()


class ProposalError(Exception):
    """Envelope verification failed — tampered or stale proposal."""


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


def asset_key(amount) -> str:
    """Spend-limit key for an amount: 'XRP' or 'CUR.issuer'."""
    if isinstance(amount, str):  # XRP, in drops
        return "XRP"
    return f"{display_currency(amount['currency'])}.{amount['issuer']}"


def amount_value(amount) -> Decimal:
    """Decimal value of an amount in its own units (XRP, not drops)."""
    from xrpl.utils import drops_to_xrp
    if isinstance(amount, str):
        return Decimal(drops_to_xrp(amount))
    return Decimal(amount["value"])


def load_approved():
    try:
        return json.loads(APPROVED_PATH.read_text()).get("pairs", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def approved_token_set():
    """Set of (CURRENCY, issuer) allowed by the allowlist. XRP always allowed.
    Used for single-asset actions (TrustSet, Payment)."""
    toks = {("XRP", None)}
    for p in load_approved().values():
        toks.add(norm_token(p["base"], p.get("base_issuer")))
        toks.add(norm_token(p["quote"], p.get("quote_issuer")))
    return toks


def approved_pair_set():
    """Set of frozenset({asset_a, asset_b}) — the EXACT pairs approved.
    An offer's two assets must match one approved pair exactly; a union of
    tokens is NOT enough (blocks unlisted token/token offers)."""
    pairs = set()
    for p in load_approved().values():
        a = norm_token(p["base"], p.get("base_issuer"))
        b = norm_token(p["quote"], p.get("quote_issuer"))
        if a != b:
            pairs.add(frozenset((a, b)))
    return pairs


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


# ---------- hashing / proposal envelopes ----------

def canonical_hash(obj: dict) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def tx_binary(tx_dict: dict) -> str:
    """Canonical XRPL binary serialization (hex) of the transaction."""
    from xrpl.core.binarycodec import encode
    return encode(tx_dict).upper()


def ripple_time_from_now(seconds: int) -> int:
    return int(time.time()) - RIPPLE_EPOCH + seconds


def save_proposal(tx_dict, network, account, action):
    """Build a hash-bound proposal envelope and save it. Returns (hash, path).

    The hash covers the envelope core (format, network, account, action,
    created_at, policy_version, tx_binary). No summary or price metadata is
    stored — the signer derives everything from the transaction.
    """
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    envelope = {
        "format": ENVELOPE_FORMAT,
        "network": network,
        "account": account,
        "action": action,
        "created_at": int(time.time()),
        "policy_version": POLICY_VERSION,
        "tx": tx_dict,
        "tx_binary": tx_binary(tx_dict),
    }
    core = {k: envelope[k] for k in ENVELOPE_HASH_KEYS}
    h = canonical_hash(core)
    envelope["proposal_hash"] = h
    path = PROPOSALS_DIR / f"{h}.json"
    path.write_text(json.dumps(envelope, indent=2, default=str))
    return h, path


def verify_proposal(prop: dict, path) -> dict:
    """Verify the envelope and return the authoritative tx dict.

    Raises ProposalError on any tampering, format mismatch, or stale
    policy version. The transaction is the ONLY source of truth — anything
    else in the file is untrusted.
    """
    if prop.get("format") != ENVELOPE_FORMAT:
        raise ProposalError(
            f"unsupported proposal format {prop.get('format')!r} — rebuild "
            f"with xrpl-trade v{__version__} (old proposals are invalid)")
    if prop.get("policy_version") != POLICY_VERSION:
        raise ProposalError(
            f"proposal built for policy v{prop.get('policy_version')}, "
            f"signer requires v{POLICY_VERSION} — rebuild the proposal")
    core = {k: prop.get(k) for k in ENVELOPE_HASH_KEYS}
    if any(v is None for v in core.values()):
        raise ProposalError("proposal envelope is missing bound fields")
    if canonical_hash(core) != prop.get("proposal_hash"):
        raise ProposalError(
            "proposal hash mismatch — the file was modified after the human "
            "reviewed it. Refusing.")
    if Path(path).stem != prop["proposal_hash"]:
        raise ProposalError("proposal filename does not match its hash")
    tx = prop.get("tx")
    if not isinstance(tx, dict):
        raise ProposalError("proposal has no transaction")
    if tx_binary(tx) != prop["tx_binary"]:
        raise ProposalError(
            "transaction does not match the hash-bound binary — tampered")
    return tx


def load_proposal(prefix: str):
    matches = list(PROPOSALS_DIR.glob(f"{prefix}*.json")) if PROPOSALS_DIR.exists() else []
    if not matches:
        sys.exit(f"No proposal matching {prefix!r}. See `xrpl-sign --list`.")
    if len(matches) > 1:
        sys.exit(f"Ambiguous prefix {prefix!r}: {[m.stem[:12] for m in matches]}")
    return json.loads(matches[0].read_text()), matches[0]


# ---------- derived summaries (never trust stored text) ----------

def fmt_amount(a) -> str:
    if isinstance(a, str):
        return f"{amount_value(a)} XRP"
    return (f"{a['value']} "
            f"{display_currency(a['currency'])}.{a['issuer'][:8]}…")


def short_addr(a: str) -> str:
    return a if len(a) <= 16 else f"{a[:8]}…{a[-4:]}"


def describe_tx(tx: dict, action_hint: str = "?") -> list:
    """Human-readable ceremony lines DERIVED from the transaction JSON.
    This is what the signer shows — never a stored summary."""
    ttype = tx.get("TransactionType")
    lines = [f"type:     {ttype} (proposed as: {action_hint})"]
    if ttype == "OfferCreate":
        pays, gets = tx["TakerPays"], tx["TakerGets"]
        pv, gv = amount_value(pays), amount_value(gets)
        lines += [
            f"give:     {fmt_amount(gets)}",
            f"receive:  {fmt_amount(pays)}",
        ]
        if pv > 0:
            # rate quoted both ways; orientation is the proposer's claim only
            lines.append(f"rate:     {fmt_amount(pays)} = "
                         f"{fmt_amount(gets)}")
    elif ttype == "TrustSet":
        la = tx["LimitAmount"]
        lines += [f"token:    {display_currency(la['currency'])}."
                  f"{short_addr(la['issuer'])}",
                  f"limit:    {la['value']}"]
    elif ttype == "OfferCancel":
        lines += [f"offer seq: {tx.get('OfferSequence')}"]
    elif ttype == "Payment":
        lines += [f"amount:   {fmt_amount(tx['Amount'])}",
                  f"to:       {short_addr(tx['Destination'])}"]
        tag = tx.get("DestinationTag")
        lines += [f"dest tag: {tag if tag is not None else 'NONE'}"]
    else:
        lines += [f"(no describer for {ttype} — should have been rejected)"]
    from xrpl.utils import drops_to_xrp
    lines.append(f"fee:      {drops_to_xrp(tx.get('Fee', '0'))} XRP")
    lines.append(f"sequence: {tx.get('Sequence')}")
    lines.append(f"last_ledger: {tx.get('LastLedgerSequence', 'n/a')}")
    if "Expiration" in tx:
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                            time.gmtime(tx["Expiration"] + RIPPLE_EPOCH))
        lines.append(f"expires:  {exp}")
    return lines


# ---------- strict transaction shape ----------

COMMON_FIELDS = {"Account", "TransactionType", "Fee", "Sequence",
                 "LastLedgerSequence", "SigningPubKey", "TxnSignature"}
REQUIRED_FIELDS = {
    "OfferCreate": {"TakerPays", "TakerGets"},
    "OfferCancel": {"OfferSequence"},
    "TrustSet": {"LimitAmount"},
    "Payment": {"Destination", "Amount"},
}
ALLOWED_FIELDS = {
    "OfferCreate": COMMON_FIELDS | {"TakerPays", "TakerGets", "Expiration"},
    "OfferCancel": COMMON_FIELDS | {"OfferSequence"},
    "TrustSet": COMMON_FIELDS | {"LimitAmount"},
    "Payment": COMMON_FIELDS | {"Destination", "Amount", "DestinationTag"},
}
DEFAULT_ALLOWED_TX_TYPES = ["OfferCreate", "OfferCancel", "TrustSet", "Payment"]


def validate_tx_shape(tx: dict, allowed_types) -> list:
    """Strict schema check. Returns a list of problems (empty = valid).

    Unknown transaction types are rejected outright, and every field must
    be in the per-type schema — a Payment cannot smuggle Paths, SendMax,
    DeliverMin, memos, or a tfPartialPayment flag.
    """
    problems = []
    ttype = tx.get("TransactionType")
    if ttype not in allowed_types:
        return [f"TransactionType {ttype!r} is not in the allowlist "
                f"{sorted(allowed_types)} — refusing"]
    allowed = ALLOWED_FIELDS.get(ttype, COMMON_FIELDS)
    for k in tx:
        if k not in allowed:
            problems.append(f"field {k!r} is not allowed for {ttype} — refusing")
    for k in REQUIRED_FIELDS.get(ttype, ()):
        if k not in tx:
            problems.append(f"field {k!r} is required for {ttype}")
    return problems


# ---------- tx introspection (from tx JSON only) ----------

def tx_tokens(tx):
    """All non-XRP (currency, issuer) identities touched by a tx."""
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


def tx_spends(tx):
    """Aggregated (asset_key, Decimal) amounts this tx spends.

    For offers the spent side is TakerGets (what the creator provides) —
    capping the received side would be wrong. Fee is always XRP.
    Returns a dict asset_key -> Decimal.
    """
    from xrpl.utils import drops_to_xrp
    spends = {}

    def add(key, amt):
        spends[key] = spends.get(key, Decimal(0)) + amt

    ttype = tx.get("TransactionType")
    if ttype == "OfferCreate":
        gets = tx.get("TakerGets")
        add(asset_key(gets), amount_value(gets))
    elif ttype == "Payment":
        amt = tx.get("Amount")
        add(asset_key(amt), amount_value(amt))
    # TrustSet / OfferCancel spend nothing beyond the fee
    add("XRP", Decimal(drops_to_xrp(tx.get("Fee", "0"))))
    return spends


# ---------- policy ----------

DEFAULT_POLICY = {
    "policy_version": POLICY_VERSION,
    "network_lock": "testnet",
    "max_fee_drops": 1000,
    "spend_limits": {
        "XRP": {"per_tx": "25", "per_day": "100"},
    },
    "destination_allowlist": [],  # [{"address": "r…", "destination_tag": 7|null}]
    "max_deviation_bps": 1000,
    "proposal_ttl_seconds": 86400,
    "allowed_tx_types": DEFAULT_ALLOWED_TX_TYPES,
}


def load_policy():
    if not POLICY_PATH.exists():
        sys.exit(f"No policy file. Run `xrpl-sign init-policy` first ({POLICY_PATH}).")
    try:
        pol = json.loads(POLICY_PATH.read_text())
    except json.JSONDecodeError:
        sys.exit(f"Policy file is not valid JSON: {POLICY_PATH}")
    if pol.get("policy_version") != POLICY_VERSION:
        sys.exit(f"Policy is v{pol.get('policy_version')}, signer requires "
                 f"v{POLICY_VERSION} — run `xrpl-sign migrate-policy`.")
    merged = dict(DEFAULT_POLICY)
    merged.update(pol)
    return merged


# ---------- concurrency-safe spend tracker ----------

class SpentTracker:
    """Rolling-24h per-asset spend totals with an exclusive file lock, so
    concurrent signers cannot both slip under a daily cap."""

    def __init__(self, state_path=None, lock_path=None):
        self.state_path = Path(state_path) if state_path else STATE_PATH
        self.lock_path = Path(lock_path) if lock_path else STATE_LOCK_PATH

    @contextlib.contextmanager
    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "w") as lf:
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def _load(self):
        try:
            st = json.loads(self.state_path.read_text())
            if set(st) >= {"window_start", "totals"}:
                return st
        except (FileNotFoundError, json.JSONDecodeError):
            pass
        return {"window_start": int(time.time()), "totals": {}}

    def _save(self, st):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(st))
        tmp.replace(self.state_path)

    def _prune(self, st, now):
        if now - st.get("window_start", 0) >= 86400:
            return {"window_start": now, "totals": {}}
        return st

    def check(self, spends: dict, policy) -> list:
        """Denial reasons if reserving `spends` now would breach limits.
        Does not mutate. `spends`: {asset_key: Decimal}."""
        denials = []
        with self._locked():
            st = self._prune(self._load(), int(time.time()))
            limits = policy.get("spend_limits", {})
            for asset, amt in spends.items():
                lim = limits.get(asset)
                if lim is None:
                    denials.append(
                        f"no spend limit configured for {asset} — fail closed "
                        f"(add it to spend_limits or remove the asset)")
                    continue
                if amt > Decimal(lim["per_tx"]):
                    denials.append(
                        f"{asset} spend {amt} > per-tx limit {lim['per_tx']}")
                day = Decimal(st["totals"].get(asset, "0"))
                if day + amt > Decimal(lim["per_day"]):
                    denials.append(
                        f"{asset} daily spend would be {day + amt} > "
                        f"per-day limit {lim['per_day']} (used {day})")
        return denials

    def try_reserve(self, spends: dict, policy) -> list:
        """Atomically check limits AND record the spend. Returns denials
        (empty = reserved). This is the real enforcement point."""
        denials = []
        with self._locked():
            now = int(time.time())
            st = self._prune(self._load(), now)
            limits = policy.get("spend_limits", {})
            for asset, amt in spends.items():
                lim = limits.get(asset)
                if lim is None:
                    denials.append(f"no spend limit configured for {asset} — fail closed")
                    continue
                if amt > Decimal(lim["per_tx"]):
                    denials.append(
                        f"{asset} spend {amt} > per-tx limit {lim['per_tx']}")
                day = Decimal(st["totals"].get(asset, "0"))
                if day + amt > Decimal(lim["per_day"]):
                    denials.append(
                        f"{asset} daily spend would be {day + amt} > "
                        f"per-day limit {lim['per_day']} (used {day})")
            if denials:
                return denials
            for asset, amt in spends.items():
                st["totals"][asset] = str(
                    Decimal(st["totals"].get(asset, "0")) + amt)
            self._save(st)
        return []

    def release(self, spends: dict):
        """Refund a reservation (e.g. submission failed after signing)."""
        with self._locked():
            st = self._prune(self._load(), int(time.time()))
            for asset, amt in spends.items():
                cur = Decimal(st["totals"].get(asset, "0")) - amt
                st["totals"][asset] = str(max(cur, Decimal(0)))
            self._save(st)


def audit(action, proposal_hash, tx_hash, network, account, result, note="",
          spends=None):
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
    if spends:
        entry["spends"] = {k: str(v) for k, v in spends.items()}
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
