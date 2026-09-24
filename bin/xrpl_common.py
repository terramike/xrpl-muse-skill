#!/usr/bin/env python3
"""xrpl_common v0.4: shared helpers for xrpl-trade (proposer) and xrpl-sign.

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

v0.4 hardening:
  - True rolling-24h spend window: timestamped entries, not one bucket.
  - Reservations stay PENDING through ambiguous submission outcomes;
    released only on proven failure / proven non-inclusion (sweep_pending).
  - Envelope invariants: account match, action<->type/orientation match,
    required fields, no signature material in unsigned proposals,
    created_at not from the future.
  - NaN/Infinity amounts rejected (they poison limit comparisons).
  - Signer refuses to run unless state files are owner-only.
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

__version__ = "0.4.0"
POLICY_VERSION = 3
ENVELOPE_FORMAT = "xrpl-proposal/3"
# Fields covered by the proposal hash. Everything safety-critical lives here.
# Notably: network, creation time, policy version, and the canonical binary
# transaction. Summaries are NOT stored and NOT trusted — the signer derives
# them from the transaction.
ENVELOPE_HASH_KEYS = ("format", "network", "account", "action",
                      "created_at", "policy_version", "tx_binary")
# Rolling spend window, seconds.
ROLLING_WINDOW = 86400
# Max allowed clock skew for proposal created_at (seconds in the future).
MAX_FUTURE_SKEW = 300


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
    if not d.is_finite():
        sys.exit(f"{name} must be a finite number, got {s!r}.")
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
    try:
        encoded = tx_binary(tx)
    except Exception as e:  # noqa: BLE001 — binary codec rejects NaN, etc.
        raise ProposalError(
            f"transaction cannot be canonically encoded ({e}) — refusing")
    if encoded != prop["tx_binary"]:
        raise ProposalError(
            "transaction does not match the hash-bound binary — tampered")
    return tx


def verify_envelope_invariants(prop: dict, tx: dict):
    """Defense-in-depth checks on the envelope beyond the hash.

    Raises ProposalError when the envelope is internally inconsistent:
    account mismatch, action/type (or buy/sell orientation) mismatch,
    missing required fields, signature material in an unsigned proposal,
    or a created_at unreasonably far in the future.
    """
    if prop.get("account") != tx.get("Account"):
        raise ProposalError(
            f"envelope account {prop.get('account')!r} != transaction "
            f"Account {tx.get('Account')!r} — refusing")
    ttype = tx.get("TransactionType")
    action = prop.get("action")
    expected = {"OfferCreate": ("buy", "sell"), "TrustSet": ("trustline",),
                "OfferCancel": ("cancel",), "Payment": ("send",)}
    if action not in expected.get(ttype, ()):
        raise ProposalError(
            f"envelope action {action!r} does not match transaction type "
            f"{ttype!r} — refusing")
    for f in ("Account", "Fee", "Sequence", "LastLedgerSequence"):
        if f not in tx:
            raise ProposalError(
                f"transaction missing required field {f!r} — refusing")
    if "TxnSignature" in tx or "SigningPubKey" in tx:
        raise ProposalError(
            "unsigned proposal carries TxnSignature/SigningPubKey — refusing")
    now = int(time.time())
    if prop.get("created_at", 0) > now + MAX_FUTURE_SKEW:
        raise ProposalError(
            "proposal created_at is unreasonably far in the future — refusing")
    if ttype == "OfferCreate" and action in ("buy", "sell"):
        # orientation: buy <=> TakerPays is BASE, sell <=> TakerGets is BASE
        pays, gets = tx.get("TakerPays"), tx.get("TakerGets")
        pay_tok = norm_token(pays["currency"] if isinstance(pays, dict) else "XRP",
                             pays.get("issuer") if isinstance(pays, dict) else None)
        get_tok = norm_token(gets["currency"] if isinstance(gets, dict) else "XRP",
                             gets.get("issuer") if isinstance(gets, dict) else None)
        for p in load_approved().values():
            base = norm_token(p["base"], p.get("base_issuer"))
            quote = norm_token(p["quote"], p.get("quote_issuer"))
            if base != quote and {base, quote} == {pay_tok, get_tok}:
                want_buy = (pay_tok == base and get_tok == quote)
                if action == "buy" and not want_buy:
                    raise ProposalError(
                        f"envelope says 'buy' but the offer gives BASE "
                        f"({base[0]}) — orientation mismatch, refusing")
                if action == "sell" and want_buy:
                    raise ProposalError(
                        f"envelope says 'sell' but the offer takes BASE "
                        f"({base[0]}) — orientation mismatch, refusing")
                break


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


def is_valid_classic_address(addr: str) -> bool:
    """Real XRPL base58-checksum validation, not startswith('r')."""
    try:
        from xrpl.core.addresscodec import is_valid_classic_address
        return is_valid_classic_address(addr)
    except ImportError:
        return isinstance(addr, str) and addr.startswith("r")


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


def validate_amounts(tx: dict) -> list:
    """Every amount/fee/sequence in the tx must be finite and sane.

    NaN or Infinity would poison limit comparisons (NaN > limit is False),
    so they are rejected outright — a fail-closed numeric boundary.
    """
    problems = []

    def num(a, label, positive=True):
        try:
            v = amount_value(a)
        except Exception:  # noqa: BLE001
            return f"{label} is not a valid amount"
        if not v.is_finite():
            return f"{label} is not finite — refusing"
        if positive and v <= 0:
            return f"{label} must be positive"
        return None

    ttype = tx.get("TransactionType")
    if ttype == "OfferCreate":
        for f in ("TakerPays", "TakerGets"):
            p = num(tx.get(f), f)
            if p:
                problems.append(p)
    elif ttype == "Payment":
        p = num(tx.get("Amount"), "Amount")
        if p:
            problems.append(p)
    elif ttype == "TrustSet":
        la = tx.get("LimitAmount", {})
        try:
            v = Decimal(str(la.get("value", "")))
        except (InvalidOperation, ValueError, TypeError):
            problems.append("LimitAmount value is not a valid number")
            v = None
        if v is not None and (not v.is_finite() or v < 0):
            problems.append("LimitAmount must be a finite non-negative number")
    for f in ("Fee", "Sequence", "LastLedgerSequence"):
        raw = tx.get(f)
        try:
            iv = int(str(raw))
            if iv <= 0:
                problems.append(f"{f} must be a positive integer")
        except (ValueError, TypeError):
            problems.append(f"{f} must be a positive integer")
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
    "max_spread_bps": 1000,      # book bid/ask spread cap for price checks
    "min_book_depth": "5",       # min pays-side depth per book side (base units)
    "max_offer_lifetime_seconds": 86400,
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


def check_protected_files():
    """Fail closed unless signer state is owner-only.

    The protected deployment boundary is: the xrpl-sign program itself,
    policy.json, approved.json, state.json, state.lock, audit.log. (The
    binary is a deployment concern — documented in SECURITY.md.) If the
    agent can rewrite policy or delete state, daily limits are fiction.
    Proposals stay agent-writable: they are treated as hostile input and
    fully verified.
    """
    problems = []
    try:
        euid = os.geteuid()
    except AttributeError:
        return  # non-POSIX: deployment must protect these another way
    for p in (POLICY_PATH, APPROVED_PATH, STATE_PATH, STATE_LOCK_PATH,
              AUDIT_PATH):
        if not p.exists():
            continue
        st = p.stat()
        if st.st_uid != euid:
            problems.append(f"{p} is not owned by the current user")
        if st.st_mode & 0o077:
            problems.append(
                f"{p} is group/world-accessible "
                f"(mode {oct(st.st_mode & 0o777)}) — run chmod 600")
    if problems:
        sys.exit("Signer state is not protected — refusing to sign:\n  "
                 + "\n  ".join(problems))


# ---------- concurrency-safe spend tracker ----------

class SpentTracker:
    """True rolling-24h per-asset spend tracker with an exclusive file lock.

    State is a list of timestamped entries (not one 24h bucket), so the
    limit cannot be doubled around a reset boundary. Entries are
    ``pending`` from reservation until the ledger outcome is known:

    - validated tesSUCCESS -> ``confirmed`` (counts toward the limit)
    - validated failure, or LastLedgerSequence passed with the tx provably
      not included -> entry dropped (released)
    - ambiguous submission error -> entry STAYS pending. It is never
      released on a guess; sweep_pending() resolves it against the ledger
      on the next signing run.

    Concurrent signers cannot both slip under a cap: check+reserve is one
    atomic section under the lock.
    """

    def __init__(self, state_path=None, lock_path=None):
        self.state_path = Path(state_path) if state_path else STATE_PATH
        self.lock_path = Path(lock_path) if lock_path else STATE_LOCK_PATH

    @contextlib.contextmanager
    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        new_lock = not self.lock_path.exists()
        with open(self.lock_path, "w") as lf:
            if new_lock:
                os.chmod(self.lock_path, 0o600)
            fcntl.flock(lf, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)

    def _load(self):
        try:
            st = json.loads(self.state_path.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return {"entries": []}
        if isinstance(st.get("entries"), list):
            return {"entries": st["entries"]}
        if isinstance(st.get("totals"), dict):
            # migrate the v0.3 single-bucket format: old totals become
            # confirmed entries stamped at the old window start
            w0 = int(st.get("window_start", 0))
            return {"entries": [
                {"rid": "migrated", "ts": w0, "asset": a,
                 "amount": str(v), "status": "confirmed",
                 "tx_hash": None, "last_ledger": None}
                for a, v in st["totals"].items()]}
        return {"entries": []}

    def _save(self, st):
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(st))
        os.chmod(tmp, 0o600)
        tmp.replace(self.state_path)

    @staticmethod
    def _prune(entries, now):
        return [e for e in entries
                if now - int(e.get("ts", 0)) < ROLLING_WINDOW]

    @staticmethod
    def _totals(entries):
        t = {}
        for e in entries:
            t[e["asset"]] = t.get(e["asset"], Decimal(0)) + Decimal(e["amount"])
        return t

    def _deny(self, spends, entries, policy):
        denials = []
        totals = self._totals(entries)
        limits = policy.get("spend_limits", {})
        for asset, amt in spends.items():
            lim = limits.get(asset)
            if lim is None:
                denials.append(
                    f"no spend limit configured for {asset} — fail closed "
                    f"(add it to spend_limits or remove the asset)")
                continue
            if not amt.is_finite():
                denials.append(f"{asset} spend {amt} is not finite — refusing")
                continue
            if amt > Decimal(lim["per_tx"]):
                denials.append(
                    f"{asset} spend {amt} > per-tx limit {lim['per_tx']}")
            day = totals.get(asset, Decimal(0))
            if day + amt > Decimal(lim["per_day"]):
                denials.append(
                    f"{asset} rolling-24h spend would be {day + amt} > "
                    f"per-day limit {lim['per_day']} (used {day})")
        return denials

    def check(self, spends: dict, policy) -> list:
        """Denial reasons if reserving `spends` now would breach limits.
        Does not mutate. `spends`: {asset_key: Decimal}."""
        with self._locked():
            entries = self._prune(self._load()["entries"], int(time.time()))
            return self._deny(spends, entries, policy)

    def try_reserve(self, spends: dict, policy):
        """Atomically check limits AND record pending entries.

        Returns (denials, reservation_id). Empty denials = reserved."""
        import uuid
        rid = uuid.uuid4().hex[:16]
        with self._locked():
            now = int(time.time())
            entries = self._prune(self._load()["entries"], now)
            denials = self._deny(spends, entries, policy)
            if denials:
                return denials, None
            for asset, amt in spends.items():
                entries.append({"rid": rid, "ts": now, "asset": asset,
                                "amount": str(amt), "status": "pending",
                                "tx_hash": None, "last_ledger": None})
            self._save({"entries": entries})
        return [], rid

    def release_reservation(self, rid):
        """Drop pending entries for a reservation that never got signed
        (e.g. bad seed, wallet mismatch). Only unbound entries are dropped."""
        if not rid:
            return
        with self._locked():
            st = self._load()
            st["entries"] = [e for e in self._prune(st["entries"], int(time.time()))
                             if not (e.get("rid") == rid
                                     and e.get("status") == "pending"
                                     and not e.get("tx_hash"))]
            self._save(st)

    def bind_reservation(self, rid, tx_hash, last_ledger):
        """Attach the signed transaction's identity to a reservation."""
        with self._locked():
            st = self._load()
            for e in st["entries"]:
                if e.get("rid") == rid and e.get("status") == "pending":
                    e["tx_hash"] = tx_hash
                    e["last_ledger"] = last_ledger
            self._save(st)

    def confirm(self, tx_hash):
        """Validated tesSUCCESS: entries stay and count toward the limit."""
        with self._locked():
            st = self._load()
            for e in st["entries"]:
                if e.get("tx_hash") == tx_hash and e.get("status") == "pending":
                    e["status"] = "confirmed"
            self._save(st)

    def release_tx(self, tx_hash):
        """Validated failure: drop the entries, freeing the budget."""
        with self._locked():
            st = self._load()
            st["entries"] = [e for e in st["entries"]
                             if e.get("tx_hash") != tx_hash]
            self._save(st)

    def sweep_pending(self, client):
        """Resolve ambiguous pending reservations against the ledger.

        For each bound pending entry whose LastLedgerSequence has passed the
        validated ledger: if the tx is on-ledger with tesSUCCESS it becomes
        confirmed; if it failed validation or provably was never included,
        the entry is dropped. Anything uncertain (RPC trouble, ledger not
        yet past) stays pending — fail closed, never release on a guess.
        """
        from xrpl.models.requests import Ledger, Tx
        with self._locked():
            now = int(time.time())
            entries = self._prune(self._load()["entries"], now)
            bound = [e for e in entries
                     if e.get("status") == "pending" and e.get("tx_hash")
                     and e.get("last_ledger")]
            if not bound:
                self._save({"entries": entries})
                return
            try:
                cur = client.request(
                    Ledger(ledger_index="validated")).result["ledger_index"]
            except Exception:  # noqa: BLE001
                self._save({"entries": entries})
                return  # cannot tell — keep everything pending
            keep = []
            for e in entries:
                if (e.get("status") == "pending" and e.get("tx_hash")
                        and e.get("last_ledger")
                        and int(e["last_ledger"]) < int(cur)):
                    try:
                        r = client.request(Tx(transaction=e["tx_hash"]))
                        ok = r.is_successful()
                        res = (r.result.get("meta", {}) or {}
                               ).get("TransactionResult") if ok else None
                    except Exception:  # noqa: BLE001
                        keep.append(e)  # uncertain — keep pending
                        continue
                    if ok and res == "tesSUCCESS":
                        e["status"] = "confirmed"
                        keep.append(e)
                    # else: validated failure or never included -> release
                else:
                    keep.append(e)
            self._save({"entries": keep})


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
    new_file = not AUDIT_PATH.exists()
    with AUDIT_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    if new_file:
        os.chmod(AUDIT_PATH, 0o600)


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
