#!/usr/bin/env python3
"""xrpl_common v0.5: shared helpers for xrpl-trade (proposer) and xrpl-sign.

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
  - Hardened price validation (both sides, spread cap, min depth,
    depth-weighted mid), fail-closed RequireDestTag.

v0.5 hardening (NFTs):
  - NFTokenMint / NFTokenCreateOffer (sell only) join the strict per-type
    schemas. Mint policy: URI hex <= max_uri_bytes, TransferFee <=
    min(policy cap, 50000 protocol max), flags restricted to a
    policy-gated set (default: transferable + burnable), mints per
    rolling 24h counted from the audit log.
  - NFTokenCreateOffer: XRP-only amounts (v1), tfSellNFToken required
    (buy offers need an Owner field, which the schema rejects outright),
    Expiration required and bounded like other offers. No book-deviation
    check — each NFTokenID is unique, there is no fungible book.

v0.5 buy side (NFTs, operator-opt-in via nft.allow_buy_offers):
  - NFTokenAcceptOffer joins the strict schemas (direct mode only:
    NFTokenSellOffer required; NFTokenBuyOffer / NFTokenBrokerFee are
    rejected). The spend lives in the referenced sell offer, not in the
    tx — the signer fetches the offer entry (fail closed) and reserves
    the XRP amount through the normal spend lifecycle.
  - Buy-side NFTokenCreateOffer (Owner set, no sell flag) is a bid: the
    bid XRP is locked like an OfferCreate's TakerGets and counts toward
    spend limits; policy caps it at nft.max_bid_xrp.
  - Anti-counterfeit is a reporting duty, not an authenticity claim: both
    proposer and signer surface the on-ledger seller, token URI, and
    taxon so the human verifies the minter. The skill never calls a
    token "authentic".
"""
import contextlib
import fcntl
import hashlib
import json
import os
import re
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
FAVORITES_PATH = XRPL_DIR / "favorites.json"    # named artist watchlist (read-only)

NETWORKS = {
    "mainnet": ["https://s1.ripple.com:51234", "https://s2.ripple.com:51234"],
    "testnet": ["https://s.altnet.rippletest.net:51234"],
    "devnet": ["https://s.devnet.rippletest.net:51234"],
}
RIPPLE_EPOCH = 946684800  # unix seconds of 2000-01-01T00:00:00Z
REQUIRE_DEST_TAG_FLAG = 0x00020000  # lsfRequireDestTag

__version__ = "0.5.0"
POLICY_VERSION = 4
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
                "OfferCancel": ("cancel",), "Payment": ("send",),
                "NFTokenMint": ("nft-mint",),
                "NFTokenCreateOffer": ("nft-list", "nft-bid"),
                "NFTokenAcceptOffer": ("nft-buy",)}
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
    if ttype == "OfferCreate" and action in ("buy", "sell"):        # orientation: buy <=> TakerPays is BASE, sell <=> TakerGets is BASE
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
    if ttype == "NFTokenCreateOffer" and action in ("nft-list", "nft-bid"):
        # orientation: nft-list <=> pure sell offer (tfSellNFToken, no
        # Owner); nft-bid <=> buy offer (Owner set, no sell flag). A
        # relabeled envelope cannot smuggle the other side past review.
        is_sell = bool(int(tx.get("Flags", 0) or 0) & NFT_SELL_FLAG)
        has_owner = "Owner" in tx
        if action == "nft-list" and (not is_sell or has_owner):
            raise ProposalError(
                "envelope says 'nft-list' but the offer is not a pure sell "
                "offer — refusing")
        if action == "nft-bid" and (is_sell or not has_owner):
            raise ProposalError(
                "envelope says 'nft-bid' but the offer is not a buy offer — "
                "refusing")


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
    elif ttype == "NFTokenMint":
        uri_raw = tx.get("URI", "")
        try:
            uri_txt = bytes.fromhex(uri_raw).decode("utf-8", "replace")
        except (ValueError, TypeError):
            uri_txt = f"<invalid hex: {uri_raw[:32]}…>"
        fee = int(tx.get("TransferFee") or 0)
        flags = int(tx.get("Flags") or 0)
        flag_names = []
        for bit, name in ((1, "burnable"), (2, "only-xrp"),
                          (4, "trustline"), (8, "transferable"),
                          (16, "mutable")):
            if flags & bit:
                flag_names.append(name)
        lines += [f"uri:      {uri_txt}",
                  f"royalty:  {fee / 1000:.3f}% (transfer fee {fee}/50000)",
                  f"flags:    {', '.join(flag_names) or 'none'}",
                  f"taxon:    {tx.get('NFTokenTaxon')}"]
    elif ttype == "NFTokenCreateOffer":
        dest = tx.get("Destination")
        owner = tx.get("Owner")
        is_sell = bool(int(tx.get("Flags", 0) or 0) & NFT_SELL_FLAG)
        side = "SELL" if is_sell else "BUY"
        lines += [f"token:    {tx.get('NFTokenID')}",
                  f"price:    {fmt_amount(tx['Amount'])} ({side} offer)"]
        if is_sell:
            lines.append(f"buyer:    {'anyone (public listing)' if not dest else short_addr(dest) + ' (private)'}")
        else:
            lines.append(f"seller:   {short_addr(owner) if owner else 'NONE'} "
                         f"(buy offer — only they can accept)")
    elif ttype == "NFTokenAcceptOffer":
        lines += [f"offer:    {tx.get('NFTokenSellOffer')} (sell-offer index)",
                  "note:     price / token / seller are re-verified from the",
                  "          ledger at signing — the index alone decides"]
    else:
        lines += [f"(no describer for {ttype} — should have been rejected)"]
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
    "NFTokenMint": {"NFTokenTaxon", "URI"},
    "NFTokenCreateOffer": {"NFTokenID", "Amount"},
    "NFTokenAcceptOffer": {"NFTokenSellOffer"},
}
ALLOWED_FIELDS = {
    "OfferCreate": COMMON_FIELDS | {"TakerPays", "TakerGets", "Expiration"},
    "OfferCancel": COMMON_FIELDS | {"OfferSequence"},
    "TrustSet": COMMON_FIELDS | {"LimitAmount"},
    "Payment": COMMON_FIELDS | {"Destination", "Amount", "DestinationTag"},
    # NOTE: no "Issuer" on NFTokenMint (minting for another issuer is out
    # of scope). NFTokenCreateOffer allows "Owner" for buy offers (bids);
    # sell offers must NOT carry it (enforced in check_nft_offer).
    "NFTokenMint": COMMON_FIELDS | {"NFTokenTaxon", "URI", "TransferFee",
                                    "Flags"},
    "NFTokenCreateOffer": COMMON_FIELDS | {"NFTokenID", "Amount",
                                           "Expiration", "Destination",
                                           "Owner", "Flags"},
    # v1 is direct-mode only: NFTokenSellOffer required; NFTokenBuyOffer
    # (accepting someone's bid = selling into it) and NFTokenBrokerFee
    # (brokered mode) are unrepresentable here.
    "NFTokenAcceptOffer": COMMON_FIELDS | {"NFTokenSellOffer"},
}
DEFAULT_ALLOWED_TX_TYPES = ["OfferCreate", "OfferCancel", "TrustSet",
                            "Payment", "NFTokenMint", "NFTokenCreateOffer",
                            "NFTokenAcceptOffer"]

# NFTokenMint flag bits (xrpl-py NFTokenMintFlag).
NFT_MINT_FLAG_NAMES = {1: "burnable", 2: "only-xrp", 4: "trustline",
                       8: "transferable", 16: "mutable"}
# Absolute protocol ceiling for TransferFee (50000 = 50%). The policy cap
# can only tighten below this.
NFT_MAX_TRANSFER_FEE = 50000
# tfSellNFToken — the only NFTokenCreateOffer flag bit v1 supports.
NFT_SELL_FLAG = 1


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
    elif ttype == "NFTokenCreateOffer":
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
    elif ttype == "NFTokenMint":
        try:
            ti = int(str(tx.get("NFTokenTaxon")))
            if not 0 <= ti <= 0xFFFFFFFF:
                problems.append("NFTokenTaxon out of uint32 range — refusing")
        except (ValueError, TypeError):
            problems.append("NFTokenTaxon must be an integer — refusing")
    for f in ("Fee", "Sequence", "LastLedgerSequence"):
        raw = tx.get(f)
        try:
            iv = int(str(raw))
            if iv <= 0:
                problems.append(f"{f} must be a positive integer")
        except (ValueError, TypeError):
            problems.append(f"{f} must be a positive integer")
    return problems


# ---------- NFT policy checks (v0.5) ----------

def nft_policy(policy: dict) -> dict:
    """The policy's nft section with v0.5 defaults. Never trust the
    operator's file to be complete — load_policy merges defaults, but
    check_policy can also be called with hand-built dicts in tests."""
    cfg = {
        "max_transfer_fee": 10000,    # out of 50000 = 10%
        "max_mints_per_day": 10,
        "allowed_mint_flags": [1, 8],  # tfBurnable + tfTransferable
        "max_uri_bytes": 256,
        # Buy side (nft-buy / nft-bid) is opt-in: accepting sell offers
        # spends XRP immediately and bids lock XRP, so the operator
        # enables it deliberately. max_bid_xrp caps a single bid.
        "allow_buy_offers": False,
        "max_bid_xrp": "10",
    }
    cfg.update(policy.get("nft") or {})
    return cfg


def check_nft_mint(tx: dict, policy: dict) -> list:
    """Policy denials for an NFTokenMint, derived from the tx + policy."""
    denials = []
    cfg = nft_policy(policy)

    uri = tx.get("URI", "")
    try:
        raw = bytes.fromhex(uri) if isinstance(uri, str) else None
    except (ValueError, TypeError):
        raw = None
    if raw is None:
        denials.append("NFTokenMint URI is not valid hex — refusing")
    elif len(raw) == 0:
        denials.append("NFTokenMint URI is empty — refusing")
    elif len(raw) > int(cfg["max_uri_bytes"]):
        denials.append(
            f"NFTokenMint URI is {len(raw)} bytes > max "
            f"{cfg['max_uri_bytes']} — refusing")

    try:
        fee = int(str(tx.get("TransferFee", 0)))
    except (ValueError, TypeError):
        denials.append("TransferFee must be an integer — refusing")
        fee = None
    if fee is not None:
        cap = min(int(cfg["max_transfer_fee"]), NFT_MAX_TRANSFER_FEE)
        if not 0 <= fee <= cap:
            denials.append(
                f"TransferFee {fee} outside [0, {cap}] "
                f"(policy cap {cfg['max_transfer_fee']}, protocol max "
                f"{NFT_MAX_TRANSFER_FEE}) — refusing")

    try:
        flags = int(str(tx.get("Flags", 0)))
    except (ValueError, TypeError):
        denials.append("Flags must be an integer — refusing")
        flags = None
    if flags is not None:
        allowed_bits = 0
        for b in cfg["allowed_mint_flags"]:
            allowed_bits |= int(b)
        if flags & ~allowed_bits:
            names = ", ".join(
                NFT_MINT_FLAG_NAMES.get(b, f"bit{b}")
                for b in NFT_MINT_FLAG_NAMES if flags & b and not allowed_bits & b)
            denials.append(
                f"mint flags {flags} include disallowed bits ({names}) — "
                f"policy allows {sorted(cfg['allowed_mint_flags'])}; refusing")

    return denials


def check_nft_offer(tx: dict, policy: dict) -> list:
    """Policy denials for an NFTokenCreateOffer — sell offers AND buy
    offers (bids). A buy offer is identified by the Owner field."""
    denials = []
    cfg = nft_policy(policy)

    nid = tx.get("NFTokenID", "")
    if not (isinstance(nid, str) and len(nid) == 64
            and all(c in "0123456789abcdefABCDEF" for c in nid)):
        denials.append("NFTokenID must be 64 hex characters — refusing")

    try:
        flags = int(str(tx.get("Flags", 0)))
    except (ValueError, TypeError):
        denials.append("Flags must be an integer — refusing")
        flags = None

    owner = tx.get("Owner")
    is_buy = owner is not None

    if is_buy:
        # ---- buy offer (bid) ----
        if not cfg.get("allow_buy_offers", False):
            denials.append(
                "nft buy side is disabled by policy "
                "(nft.allow_buy_offers=false) — refusing")
        if flags is not None:
            if flags & NFT_SELL_FLAG:
                denials.append(
                    "buy offer must not set tfSellNFToken — refusing")
            if flags & ~NFT_SELL_FLAG:
                denials.append(
                    f"unknown NFTokenCreateOffer flag bits in {flags} — "
                    f"refusing")
        amt = tx.get("Amount")
        if not isinstance(amt, str):
            denials.append("v1 bids are XRP-only (Amount must be drops) — "
                           "refusing")
        else:
            try:
                from xrpl.utils import drops_to_xrp
                bid = Decimal(drops_to_xrp(amt))
            except Exception:  # noqa: BLE001
                denials.append("bid Amount is not valid drops — refusing")
                bid = None
            if bid is not None:
                cap = Decimal(str(cfg.get("max_bid_xrp", "10")))
                if bid > cap:
                    denials.append(
                        f"bid {bid} XRP > policy max_bid_xrp {cap} — refusing")
        if not is_valid_classic_address(owner):
            denials.append("Owner is not a valid classic address — refusing")
    else:
        # ---- sell offer ----
        if flags is not None:
            if not flags & NFT_SELL_FLAG:
                denials.append(
                    "only SELL offers are supported (tfSellNFToken required) "
                    "— refusing")
            if flags & ~NFT_SELL_FLAG:
                denials.append(
                    f"unknown NFTokenCreateOffer flag bits in {flags} — "
                    f"refusing")
        if not isinstance(tx.get("Amount"), str):
            denials.append("v1 listings are XRP-only (Amount must be drops) — "
                           "refusing")

    dest = tx.get("Destination")
    if dest is not None and not is_valid_classic_address(dest):
        denials.append("Destination is not a valid classic address — refusing")

    return denials


# Synthetic asset key for the rolling NFT mint quota. Mint counts are not
# currency spends, but they reserve through the same atomic SpentTracker
# lifecycle so parallel signers cannot overshoot the cap.
NFT_MINT_ASSET = "NFT_MINT"


def check_mint_rate(policy: dict, tracker) -> list:
    """Provisional (non-mutating) rolling-24h mint check.

    Pending reservations count, so a second concurrent signer sees the
    first signer's in-flight mint. The atomic reservation happens at
    signing time in xrpl-sign.
    """
    cfg = nft_policy(policy)
    cap = int(cfg["max_mints_per_day"])
    return tracker.check_count(NFT_MINT_ASSET, 1, cap)


def fetch_nft_offer_entry(client, offer_index: str):
    """Fetch an NFTokenOffer ledger entry by its index. Returns
    (entry_dict, problem). problem is None on success. Fail closed:
    any lookup failure is a problem, never an assumption."""
    from xrpl.models.requests import LedgerEntry
    if not (isinstance(offer_index, str) and len(offer_index) == 64
            and all(c in "0123456789abcdefABCDEF" for c in offer_index)):
        return None, ("offer index must be 64 hex characters — refusing")
    try:
        r = client.request(LedgerEntry(index=offer_index.upper()))
    except Exception as e:  # noqa: BLE001
        return None, (f"could not read the offer from the ledger: {e} — "
                       f"refusing")
    if not r.is_successful():
        return None, (f"offer not on ledger (entryNotFound or node error) — "
                       f"refusing")
    node = (r.result or {}).get("node")
    if not isinstance(node, dict):
        return None, "ledger returned a malformed offer entry — refusing"
    return node, None


def fetch_nft_meta(client, owner: str, nftoken_id: str):
    """On-ledger NFT metadata (URI text, taxon) for one token. Returns
    (uri_text, taxon, problem). A missing token is a problem — this is
    the counterfeit check: the seller must actually own the token on
    the ledger right now."""
    from xrpl.models.requests import AccountNFTs
    marker = None
    while True:
        try:
            r = client.request(AccountNFTs(account=owner, limit=400,
                                           marker=marker))
        except Exception as e:  # noqa: BLE001
            return None, None, (f"could not read the seller's NFTs: {e} — "
                                f"refusing")
        if not r.is_successful():
            return None, None, ("could not read the seller's NFTs "
                                "(node error) — refusing")
        for n in (r.result or {}).get("account_nfts", []):
            if n.get("NFTokenID") == nftoken_id:
                uri_hex = n.get("URI", "")
                try:
                    uri_txt = bytes.fromhex(uri_hex).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    uri_txt = "<uri is not valid hex>"
                return uri_txt, n.get("NFTokenTaxon"), None
        marker = (r.result or {}).get("marker")
        if not marker:
            break
    return None, None, ("token not found in the seller's inventory — the "
                       "seller may no longer own it — refusing")


def nft_sell_offer_report(client, offer_index: str):
    """Full verification of an NFT sell offer from the ledger.

    Returns (report_lines, denials, xrp_amount_or_None). The report is
    the anti-counterfeit ceremony: seller, token id, price, on-ledger
    URI and taxon — facts for the human to judge, never an authenticity
    claim."""
    from xrpl.utils import drops_to_xrp
    lines = []
    entry, problem = fetch_nft_offer_entry(client, offer_index)
    if problem:
        return [], [problem], None
    if entry.get("LedgerEntryType") != "NFTokenOffer":
        return [], [f"ledger entry is {entry.get('LedgerEntryType')}, not an "
                    f"NFT offer — refusing"], None
    flags = int(entry.get("Flags", 0) or 0)
    if not flags & NFT_SELL_FLAG:
        return [], ["the offer is a BUY offer, not a sell offer — "
                    "nft-buy only accepts sell offers — refusing"], None
    amount = entry.get("Amount")
    if not isinstance(amount, str):
        return [], ["sell offer is denominated in an IOU — v1 nft-buy is "
                    "XRP-only — refusing"], None
    try:
        price = Decimal(drops_to_xrp(amount))
    except Exception:  # noqa: BLE001
        return [], ["sell offer amount is not valid drops — refusing"], None
    seller = entry.get("Owner", "?")
    nid = entry.get("NFTokenID", "?")
    uri_txt, taxon, meta_problem = fetch_nft_meta(client, seller, nid)
    lines.append(f"offer:    {offer_index.upper()}")
    lines.append(f"seller:   {seller}")
    lines.append(f"token:    {nid}")
    lines.append(f"price:    {price} XRP")
    if meta_problem:
        return lines, [meta_problem], None
    if len(uri_txt) > 120:
        uri_txt = uri_txt[:117] + "..."
    lines.append(f"uri:      {uri_txt}")
    lines.append(f"taxon:    {taxon}")
    expiry = entry.get("Expiration")
    if expiry is not None:
        import datetime as _dt
        unix = expiry + 946684800
        lines.append(
            "expires:  " + _dt.datetime.fromtimestamp(
                unix, tz=_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    return lines, [], price


# ---------- artist favorites (read-only watchlist) ----------

class FavoritesError(ValueError):
    """The favorites file is corrupt or an operation is invalid."""


FAVORITE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
XRP_CAFE_NFT_URL = "https://xrp.cafe/nft/{}"
# account_tx pages per favorite per nft-new run (newest-first, so a few
# pages cover any sane artist wallet; the window stop-condition usually
# fires long before the cap).
NFT_NEW_MAX_PAGES = 5
NFT_NEW_PAGE_LIMIT = 200


def load_favorites(path=None):
    """Load the named watchlist. {} when absent. Raises FavoritesError
    on corrupt JSON — fail loud, never silently empty."""
    p = Path(path) if path else FAVORITES_PATH
    if not p.exists():
        return {}
    try:
        favs = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise FavoritesError(
            f"favorites file is unreadable ({p}): {e} — fix or delete it")
    if not isinstance(favs, dict):
        raise FavoritesError(f"favorites file is not a JSON object ({p})")
    return favs


def save_favorites(favs, path=None):
    """Persist the watchlist atomically, owner-only 0600."""
    p = Path(path) if path else FAVORITES_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(favs, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def validate_favorite_name(name):
    """Returns a problem string, or None when the name is usable."""
    if not isinstance(name, str) or not FAVORITE_NAME_RE.match(name):
        return (f"favorite name {name!r} is invalid — use 1-32 chars: "
                "lowercase letters, digits, '-' or '_'")
    return None


def resolve_fav_or_addr(token, favs):
    """Resolve a favorite name or classic address for READ commands.
    Returns (address, problem). Favorites take precedence; anything
    else is a problem, never a guess. Writes never use this — exact
    addresses only."""
    if isinstance(token, str) and token in favs \
            and isinstance(favs[token], dict):
        return favs[token].get("address"), None
    if is_valid_classic_address(token):
        return token, None
    return None, (f"{token!r} is neither a favorite name nor a valid "
                  "classic address (base58 checksum failed)")


def decode_nft_uri(uri_hex, limit=90):
    """Hex-decode an NFToken URI for display. Never raises."""
    try:
        txt = bytes.fromhex(uri_hex or "").decode("utf-8", "replace")
    except (ValueError, TypeError):
        return "<uri is not valid hex>"
    if len(txt) > limit:
        txt = txt[:limit - 1] + "…"
    return txt


def get_validated_ledger(client):
    """Current validated ledger index. Returns (index, problem)."""
    from xrpl.models.requests import Ledger
    try:
        r = client.request(Ledger(ledger_index="validated"))
    except Exception as e:  # noqa: BLE001
        return None, f"could not read the validated ledger: {e}"
    if not r.is_successful():
        return None, f"could not read the validated ledger: {r.result}"
    idx = (r.result or {}).get("ledger_index")
    if not isinstance(idx, int):
        return None, "validated ledger response had no ledger_index"
    return idx, None


def _entry_ripple_date(entry, tx):
    """Ripple-epoch date for an account_tx entry.

    Prefers the transaction's own ``date``; falls back to the entry's
    ``close_time_iso`` (ledger close time) when the node omits it.
    Returns None when neither is available.
    """
    ripple_date = tx.get("date")
    if isinstance(ripple_date, int):
        return ripple_date
    iso = entry.get("close_time_iso")
    if isinstance(iso, str):
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
            unix = int(dt.replace(tzinfo=timezone.utc).timestamp())
            return unix - RIPPLE_EPOCH
        except (ValueError, OverflowError):
            return None
    return None


def extract_mint_token_ids(meta):
    """NFTokenIDs created by one NFTokenMint, from its tx metadata.

    A first mint creates the NFTokenPage (CreatedNode/NewFields); later
    mints modify it (ModifiedNode) — those are found by diffing
    FinalFields against PreviousFields. The metadata's top-level
    ``nftoken_id`` (present on some nodes) is used as a fallback.
    Returns a list (usually one). Never raises.
    """
    if not isinstance(meta, dict):
        return []
    created, final_ids, prev_ids = [], set(), set()
    for node in meta.get("AffectedNodes", []) or []:
        if not isinstance(node, dict):
            continue
        for kind in ("CreatedNode", "ModifiedNode"):
            nd = node.get(kind)
            if not isinstance(nd, dict):
                continue
            if nd.get("LedgerEntryType") != "NFTokenPage":
                continue
            new_fields = nd.get("NewFields") or {}
            for t in new_fields.get("NFTokens", []) or []:
                nid = (t.get("NFToken") or {}).get("NFTokenID")
                if nid:
                    created.append(nid)
            for fkey, dest in (("FinalFields", final_ids),
                               ("PreviousFields", prev_ids)):
                for t in (nd.get(fkey) or {}).get("NFTokens", []) or []:
                    nid = (t.get("NFToken") or {}).get("NFTokenID")
                    if nid:
                        dest.add(nid)
    if created:
        return created
    diffed = sorted(final_ids - prev_ids)
    if diffed:
        return diffed
    # Some nodes echo the minted token at the metadata top level.
    nid = meta.get("nftoken_id")
    return [nid] if nid else []


def scan_artist_mints(client, address, stop_ledger=None, cutoff_unix=None,
                      max_pages=NFT_NEW_MAX_PAGES,
                      page_limit=NFT_NEW_PAGE_LIMIT):
    """Newest-first account_tx walk filtered to NFTokenMint.

    Stops at the first tx at/past stop_ledger (watermark) or older than
    cutoff_unix, or after max_pages. Returns (mints, pages_used,
    problem). Each mint: {ledger_index, date_unix, uri_hex, taxon,
    token_ids}. A lookup failure is a soft problem for the caller to
    report per-favorite — this is a read-only digest, not a gate."""
    from xrpl.models.requests import AccountTx
    mints, marker, pages = [], None, 0
    while True:
        try:
            r = client.request(AccountTx(account=address, limit=page_limit,
                                         marker=marker))
        except Exception as e:  # noqa: BLE001
            return mints, pages, f"account_tx failed: {e}"
        if not r.is_successful():
            return mints, pages, \
                f"account_tx failed: {(r.result or {}).get('error', r.result)}"
        for entry in (r.result or {}).get("transactions", []) or []:
            if not isinstance(entry, dict):
                continue
            li = entry.get("ledger_index")
            if stop_ledger is not None and isinstance(li, int) \
                    and li <= stop_ledger:
                return mints, pages + 1, None
            tx = entry.get("tx") or entry.get("tx_json") or {}
            if tx.get("TransactionType") != "NFTokenMint":
                continue
            ripple_d = _entry_ripple_date(entry, tx)
            unix = ripple_d + RIPPLE_EPOCH \
                if isinstance(ripple_d, (int, float)) else None
            if cutoff_unix is not None and unix is not None \
                    and unix < cutoff_unix:
                return mints, pages + 1, None
            mints.append({
                "ledger_index": li,
                "date_unix": unix,
                "uri_hex": tx.get("URI", ""),
                "taxon": tx.get("NFTokenTaxon"),
                "token_ids": extract_mint_token_ids(
                    entry.get("meta") or entry.get("metaData")),
            })
        marker = (r.result or {}).get("marker")
        pages += 1
        if not marker or pages >= max_pages:
            break
    return mints, pages, None


def nft_sell_price(client, nft_id):
    """Cheapest current listing for one token. Returns (price_text,
    problem): price_text is None when not listed; problem is a soft
    lookup failure (best-effort read, not a gate)."""
    from xrpl.models.requests import NFTSellOffers
    try:
        r = client.request(NFTSellOffers(nft_id=nft_id))
    except Exception as e:  # noqa: BLE001
        return None, f"sell-offer lookup failed: {e}"
    if not r.is_successful():
        return None, "sell-offer lookup failed"
    offers = (r.result or {}).get("offers", []) or []
    if not offers:
        return None, None
    xrp = []
    for o in offers:
        a = o.get("Amount")
        if isinstance(a, str):
            try:
                from xrpl.utils import drops_to_xrp
                xrp.append((Decimal(drops_to_xrp(a)), o))
            except Exception:  # noqa: BLE001
                continue
    if xrp:
        return fmt_amount(min(xrp, key=lambda p: p[0])[1]["Amount"]), None
    return fmt_amount(offers[0].get("Amount")), None


def check_nft_accept_offer(tx: dict, client, policy: dict):
    """Policy denials for an NFTokenAcceptOffer + the XRP amount it will
    spend (fetched from the live offer entry). Returns (denials,
    xrp_amount_or_None)."""
    denials = []
    if not nft_policy(policy).get("allow_buy_offers", False):
        return (["nft buy side is disabled by policy "
                 "(nft.allow_buy_offers=false) — refusing"], None)
    offer_index = tx.get("NFTokenSellOffer", "")
    _lines, od, amount = nft_sell_offer_report(client, offer_index)
    denials.extend(od)
    if denials:
        return denials, None
    return [], amount


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
    # TrustSet / OfferCancel / NFTokenMint / NFTokenCreateOffer (sell)
    # spend nothing beyond the fee. Buy offers (bids) DO spend: the bid
    # XRP locks in the offer, so it counts like OfferCreate's TakerGets.
    # (NFTokenAcceptOffer's spend lives in the referenced sell offer —
    # the signer folds it in via check_nft_accept_offer.)
    if ttype == "NFTokenCreateOffer":
        amt = tx.get("Amount")
        if tx.get("Owner") is not None and isinstance(amt, str):
            add("XRP", Decimal(drops_to_xrp(amt)))
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
    "nft": {
        "max_transfer_fee": 10000,    # out of 50000 = 10%
        "max_mints_per_day": 10,
        "allowed_mint_flags": [1, 8],  # tfBurnable + tfTransferable
        "max_uri_bytes": 256,
        "allow_buy_offers": False,    # opt-in: nft-buy / nft-bid
        "max_bid_xrp": "10",          # per-bid cap when buys are enabled
    },
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
    policy.json, approved.json, favorites.json, state.json, state.lock,
    audit.log. (The
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
    for p in (POLICY_PATH, APPROVED_PATH, FAVORITES_PATH, STATE_PATH,
              STATE_LOCK_PATH, AUDIT_PATH):
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

    # ---- synthetic count reservations (NFT mint quota) ----
    #
    # A mint is not a currency spend, but the rolling cap needs the same
    # atomicity: check+reserve in one locked section so parallel signers
    # cannot both slip under the cap. Count entries ride the normal
    # pending -> bound -> confirmed/released lifecycle, so sweep_pending()
    # and ambiguous-submission handling work unchanged.

    @staticmethod
    def _count(entries, asset):
        return sum(int(e.get("amount", "0")) for e in entries
                   if e.get("asset") == asset)

    def check_count(self, asset, amount, cap) -> list:
        """Denial reasons if reserving `amount` more of `asset` would breach
        `cap`. Does not mutate."""
        with self._locked():
            entries = self._prune(self._load()["entries"], int(time.time()))
            n = self._count(entries, asset)
            if n + amount > cap:
                return [f"{asset}: {n} in the last 24h + {amount} would "
                        f"exceed cap {cap} — refusing"]
            return []

    def try_reserve_count(self, asset, amount, cap):
        """Atomically check a count cap AND record a pending count entry.

        Returns (denials, reservation_id). Empty denials = reserved."""
        import uuid
        rid = uuid.uuid4().hex[:16]
        with self._locked():
            now = int(time.time())
            entries = self._prune(self._load()["entries"], now)
            n = self._count(entries, asset)
            if n + amount > cap:
                return ([f"{asset}: {n} in the last 24h + {amount} would "
                         f"exceed cap {cap} — refusing"], None)
            entries.append({"rid": rid, "ts": now, "asset": asset,
                            "amount": str(amount), "status": "pending",
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
