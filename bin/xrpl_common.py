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
PROFILE_PATH = XRPL_DIR / "profile.json"      # local assistant profile (onboarding)
PROFILE_SCHEMA_VERSION = 1
STAGE_DIR = XRPL_DIR / "stage"  # nft-stage records: review before pinning
# P1-4: the ONLY directory artwork may be staged/pinned from. Overridable
# via the "media_dir" key in config.json (operator-owned, 0600); never via
# an environment variable (agent-settable). xrpl_pin.protected_media_dir()
# resolves the effective value.
NFT_MEDIA_DIR_DEFAULT = XRPL_DIR / "media"
# P1-1: named signing profiles binding account+network+credential+policy+state.
# The signer resolves EVERYTHING from the profile on mainnet; --policy and
# --seed-env are testnet-only escape hatches and are rejected on mainnet.
PROFILES_PATH = XRPL_DIR / "profiles.json"
PROFILES_SCHEMA_VERSION = 1
# Credential kinds. "env" = one-time injection (the only mainnet kind besides
# future hardware/xaman flows). "file" = seed stored in a local file —
# TESTNET ONLY, refused on mainnet.
CRED_KIND_ENV = "env"
CRED_KIND_FILE = "file"

NETWORKS = {
    "mainnet": ["https://s1.ripple.com:51234", "https://s2.ripple.com:51234"],
    "testnet": ["https://s.altnet.rippletest.net:51234"],
    "devnet": ["https://s.devnet.rippletest.net:51234"],
}
RIPPLE_EPOCH = 946684800  # unix seconds of 2000-01-01T00:00:00Z
REQUIRE_DEST_TAG_FLAG = 0x00020000  # lsfRequireDestTag

__version__ = "0.8.0-dev"
POLICY_VERSION = 4
# Envelope v4 (P1-1 approval binding): adds the bound signing profile name
# and the sha256 of the exact policy file the human reviewed against.
# v3 and older proposals are REJECTED — regenerate them.
ENVELOPE_FORMAT = "xrpl-proposal/5"
# Fields covered by the proposal hash. Everything safety-critical lives here.
# Notably: network, creation time, policy version, the bound profile, the
# policy digest, and the canonical binary transaction. Summaries are NOT
# stored and NOT trusted — the signer derives them from the transaction.
ENVELOPE_HASH_KEYS = ("format", "network", "account", "action",
                      "created_at", "policy_version", "profile",
                      "policy_sha256", "profile_sha256", "tx_binary")
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


def save_proposal(tx_dict, network, account, action, profile=None,
                policy_sha256=None, profile_sha256=None):
    """Build a hash-bound proposal envelope and save it. Returns (hash, path).

    The hash covers the envelope core (format, network, account, action,
    created_at, policy version, BOUND PROFILE, POLICY DIGEST, tx_binary).
    No summary or price metadata is
    stored — the signer derives everything from the transaction.
    """
    # Every proposal needs an explicit signing identity. Named mainnet
    # profiles are mandatory; unprofiled testnet/devnet helpers bind the
    # isolated adhoc identity and the currently selected local policy.
    if profile is None:
        if network == "mainnet":
            raise ProposalError("mainnet proposal requires a named signing profile")
        if network not in ("testnet", "devnet"):
            raise ProposalError("unprofiled proposals are testnet/devnet only")
        profile = "adhoc-testnet"
    if policy_sha256 is None:
        pp = GIVEAWAY_POLICY_PATH if action == GIFT_ACTION else POLICY_PATH
        if not pp.exists():
            raise ProposalError(f"proposal policy file is missing: {pp}")
        policy_sha256 = _sha256_file(pp)
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    envelope = {
        "format": ENVELOPE_FORMAT,
        "network": network,
        "account": account,
        "action": action,
        "created_at": int(time.time()),
        "policy_version": POLICY_VERSION,
        "profile": profile,
        "profile_sha256": profile_sha256 or proposal_profile_fingerprint(profile),
        "policy_sha256": policy_sha256,
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
                "OfferCancel": ("cancel",), "Payment": ("send", "giveaway-gift"),
                "NFTokenMint": ("nft-mint",),
                "NFTokenCreateOffer": ("nft-list", "nft-send", "nft-bid",
                                       "giveaway-gift"),
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
    if ttype == "OfferCreate" and action in ("buy", "sell"):        # orientation: buy <=> TakerPays is BASE (creator buys base, sells quote); sell <=> TakerPays is QUOTE (creator buys quote, sells base)
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
                        f"envelope says 'buy' but TakerPays is QUOTE "
                        f"({quote[0]}) — orientation mismatch, refusing")
                if action == "sell" and want_buy:
                    raise ProposalError(
                        f"envelope says 'sell' but TakerPays is BASE "
                        f"({base[0]}) — orientation mismatch, refusing")
                break
    if ttype == "NFTokenCreateOffer" and action in ("nft-list", "nft-send",
                                                    "nft-bid"):
        # orientation: nft-list <=> pure SELL offer (tfSellNFToken, no
        # Owner, positive XRP price); nft-send <=> TRANSFER (tfSellNFToken,
        # no Owner, Destination set, 0-drops Amount — a gift, not a sale);
        # nft-bid <=> buy offer (Owner set, no sell flag). A relabeled
        # envelope cannot smuggle one side past review, and a sale can
        # never be relabeled as a gift (or vice versa).
        is_sell = bool(int(tx.get("Flags", 0) or 0) & NFT_SELL_FLAG)
        has_owner = "Owner" in tx
        has_dest = bool(tx.get("Destination"))
        amt = tx.get("Amount")
        is_zero = isinstance(amt, str) and amt == "0"
        if action == "nft-list" and (not is_sell or has_owner or is_zero):
            raise ProposalError(
                "envelope says 'nft-list' but the offer is not a priced "
                "sell offer — refusing")
        if action == "nft-send" and (not is_sell or has_owner or not has_dest
                                    or not is_zero):
            raise ProposalError(
                "envelope says 'nft-send' but the offer is not a 0-XRP "
                "transfer (sell flag + Destination + 0 drops required) — "
                "refusing")
        if action == "nft-bid" and (is_sell or not has_owner):
            raise ProposalError(
                "envelope says 'nft-bid' but the offer is not a buy offer — "
                "refusing")


def load_proposal(prefix: str):
    if not re.fullmatch(r"[0-9a-f]{1,64}", prefix or ""):
        sys.exit("Proposal hash must be 1..64 lowercase hexadecimal characters")
    matches = list(PROPOSALS_DIR.glob(f"{prefix}*.json")) if PROPOSALS_DIR.exists() else []
    if not matches:
        sys.exit(f"No proposal matching {prefix!r}. See `xrpl-sign --list`.")
    if len(matches) > 1:
        sys.exit(f"Ambiguous prefix {prefix!r}: {[m.stem[:12] for m in matches]}")
    return json.loads(matches[0].read_text()), matches[0]


def require_full_hash_for_approve(cli_hash, proposal: dict):
    """Fail closed unless the CLI --hash names the proposal EXACTLY.

    Prefixes stay read-only: reviewing a proposal with a short prefix is
    fine, but --approve (the human's signing decision) must carry the
    complete 64-char proposal hash they reviewed. A prefix could match a
    different file than the one on screen (or be re-pointed at one), so
    signing on a prefix is refused. Raises SystemExit with the exact
    re-runnable commands.
    """
    full = proposal.get("proposal_hash")
    if cli_hash != full:
        sys.exit(
            "Refusing to sign: --approve requires the FULL 64-character "
            f"proposal hash, not a prefix ({cli_hash!r}).\n"
            f"  review:  xrpl-sign --hash {full}\n"
            f"  approve: xrpl-sign --hash {full} --approve")

# ---------- signing profiles (P1-1) ----------
#
# A profile binds account + network + credential reference + policy file +
# spend-state selection into ONE named unit. The signer resolves everything
# from the profile on mainnet; independent --policy / --seed-env selection
# is rejected there. Cross-profile use (a proposal bound to profile A signed
# under profile B) is rejected BEFORE any credential is touched.

def _sha256_file(path) -> str:
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_profiles():
    """Load and validate profiles.json. Returns {name: profile}."""
    if not PROFILES_PATH.exists():
        return {}
    try:
        raw = json.loads(PROFILES_PATH.read_text())
    except (json.JSONDecodeError, OSError) as e:
        sys.exit(f"profiles: {PROFILES_PATH} unreadable: {e}")
    if not isinstance(raw, dict) or raw.get("schema_version") != PROFILES_SCHEMA_VERSION:
        sys.exit(f"profiles: {PROFILES_PATH} has wrong schema_version "
                 f"(want {PROFILES_SCHEMA_VERSION})")
    if set(raw) != {"schema_version", "profiles"}:
        sys.exit("profiles: unknown or missing document fields")
    profiles = raw.get("profiles", {})
    if not isinstance(profiles, dict):
        sys.exit(f"profiles: {PROFILES_PATH} 'profiles' must be an object")
    for name, pf in profiles.items():
        if not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", name) or name == "adhoc-testnet":
            sys.exit("profiles: invalid or reserved profile name")
        fields = {"network", "account", "credential", "policy_path", "policy_sha256", "state"}
        if not isinstance(pf, dict) or set(pf) != fields:
            sys.exit("profiles: unknown or missing profile fields")
        if not isinstance(pf["policy_path"], str) or not Path(pf["policy_path"]).is_absolute():
            sys.exit("profiles: policy_path must be absolute")
        if not isinstance(pf["policy_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", pf["policy_sha256"]):
            sys.exit("profiles: invalid policy digest")
        if not isinstance(pf["network"], str):
            sys.exit("profiles: invalid network")
        for key in ("network", "account", "credential", "policy_path", "state"):
            if key not in pf:
                sys.exit(f"profiles: profile {name!r} missing {key!r}")
        if pf["network"] not in NETWORKS:
            sys.exit(f"profiles: profile {name!r} unknown network")
        if not is_valid_classic_address(pf["account"]):
            sys.exit(f"profiles: profile {name!r} has invalid account")
        cred = pf["credential"]
        if not isinstance(cred, dict):
            sys.exit("profiles: credential must be an object")
        expected = {"kind", "env_var"} if cred.get("kind") == "env" else {"kind", "path"}
        if set(cred) != expected:
            sys.exit("profiles: invalid credential fields")
        if cred.get("kind") == "env" and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", str(cred.get("env_var", ""))):
            sys.exit("profiles: invalid credential reference")
        if pf["network"] == "mainnet" and cred.get("kind") != "env":
            sys.exit("profiles: mainnet credentials must be vault-injected")
        if cred.get("kind") not in (CRED_KIND_ENV, CRED_KIND_FILE):
            sys.exit(f"profiles: profile {name!r} has unknown credential kind")
        if cred["kind"] == CRED_KIND_ENV and not cred.get("env_var"):
            sys.exit(f"profiles: profile {name!r} env credential needs env_var")
        if cred["kind"] == CRED_KIND_FILE and not cred.get("path"):
            sys.exit(f"profiles: profile {name!r} file credential needs path")
        if pf["state"] not in ("default", "giveaway"):
            sys.exit(f"profiles: profile {name!r} unknown state")
    return profiles


def get_profile(name):
    profiles = load_profiles()
    if name not in profiles:
        known = ", ".join(sorted(profiles)) or "(none defined)"
        sys.exit(f"unknown signing profile {name!r}. Known: {known}. "
                 f"Define profiles in {PROFILES_PATH}.")
    return profiles[name]


def proposal_profile_fingerprint(name):
    if name == "adhoc-testnet":
        return canonical_hash({"mode": "adhoc-testnet"})
    if name:
        return canonical_hash(get_profile(name))
    return None


def tracker_for_profile(profile, network, account):
    """Stable account/network namespace, unaffected by profile renaming or state edits.

    Existing legacy accounting is never silently abandoned. Recovery must first
    move/reconstruct it into this namespace under operator review.
    """
    key = canonical_hash({"network": network, "account": account})
    state = XRPL_DIR / "accounts" / key / "state.json"
    for kind, legacy in (("default", STATE_PATH), ("giveaway", GIVEAWAY_STATE_PATH)):
        if not legacy.exists():
            continue
        old_tracker = SpentTracker(legacy, legacy.with_suffix(".lock"))
        with old_tracker._locked():
            entries = old_tracker._load()["entries"]
            if not entries:
                continue
            receipt_path = legacy.with_name(legacy.name + ".migration.json")
            try:
                receipt = json.loads(receipt_path.read_text())
            except (OSError, json.JSONDecodeError):
                receipt = {}
            source_digest = _sha256_file(legacy)
            if (receipt.get("source_sha256") == source_digest
                    and receipt.get("destination_key") == key
                    and receipt.get("source_kind") == kind):
                continue
            # Fully expired confirmed records no longer represent liabilities.
            if not SpentTracker._prune(entries, int(time.time())):
                continue
            raise StateCorruptError("Legacy accounting requires explicit reviewed migration before profile signing: " + str(legacy))
    return SpentTracker(state, state.with_suffix(".lock"))


def profile_policy_digest(profile) -> str:
    """sha256 of the profile's policy file (tamper-evident binding)."""
    pp = Path(os.path.expanduser(profile["policy_path"]))
    if not pp.exists():
        sys.exit(f"profile policy file missing: {pp}")
    return _sha256_file(pp)


def check_profile_protected(profile):
    """Policy and any local test credential must be owner-only."""
    pp = Path(os.path.expanduser(profile["policy_path"]))
    paths = [(pp, "Profile policy")]
    cred = profile.get("credential", {})
    if cred.get("kind") == CRED_KIND_FILE:
        cp = Path(os.path.expanduser(cred["path"]))
        if profile["network"] == "mainnet":
            sys.exit("mainnet credentials must be vault-injected")
        require_local_network(profile["network"])
        paths.append((cp, "Local test credential"))
    for path, label in paths:
        try:
            st = path.lstat()
        except OSError as exc:
            sys.exit(f"{label} unavailable: {path}: {exc}")
        if not stat.S_ISREG(st.st_mode):
            sys.exit(f"{label} must be a regular, non-symlink file")
        if hasattr(os, "geteuid") and st.st_uid != os.geteuid():
            sys.exit(f"{label} is not owned by the signer")
        if st.st_mode & 0o077:
            sys.exit(f"refusing: {label.lower()} {path} is not owner-only "
                     f"(mode {oct(st.st_mode & 0o777)})")


def verify_profile_binding(profile_name, profile, prop):
    """Reject cross-profile use BEFORE credential access (P1-1).

    The proposal's bound profile, account, and network must all match the
    requested signing profile. A proposal built for one profile can never
    be signed under another.
    """
    if prop.get("profile") != profile_name:
        raise ProposalError(
            f"proposal is bound to profile {prop.get('profile')!r}, not "
            f"{profile_name!r} — refusing (cross-profile use)")
    if prop.get("profile_sha256") != canonical_hash(profile):
        raise ProposalError("Signing profile changed since approval; rebuild proposal")
    if prop.get("account") != profile["account"]:
        raise ProposalError(
            f"proposal account {prop.get('account')} != profile account "
            f"{profile['account']} — refusing")
    if prop.get("network") != profile["network"]:
        raise ProposalError(
            f"proposal network {prop.get('network')!r} != profile network "
            f"{profile['network']!r} — refusing")


def verify_policy_digest_binding(profile, prop):
    """The policy file on disk must match the digest bound at proposal time
    AND the digest recorded in the profile. A modified policy invalidates
    old proposals — the human must re-review under the new policy."""
    current = profile_policy_digest(profile)
    if prop.get("policy_sha256") != current:
        raise ProposalError(
            "policy file changed since this proposal was built "
            f"(proposal binds {str(prop.get('policy_sha256'))[:16]}…, "
            f"disk has {current[:16]}…) — rebuild the proposal under the "
            "current policy")
    if profile.get("policy_sha256") and profile["policy_sha256"] != current:
        raise ProposalError(
            f"profile {profile!r} records policy digest "
            f"{str(profile.get('policy_sha256'))[:16]}… but the file on disk "
            f"is {current[:16]}… — update the profile after reviewing the "
            "policy change")


def resolve_proposal_profile(network, account, action):
    """Find the signing profile a proposal binds to (P1-1).

    Returns (profile_name, profile_or_None, policy_path, policy_digest).
    Mainnet REQUIRES a defined profile — otherwise the proposal is refused.
    Testnet/devnet without a defined profile bind an ephemeral "adhoc"
    profile; the signer only honors adhoc on non-mainnet with explicit
    --policy/--seed-env flags.
    """
    profiles = load_profiles()
    want_giveaway = (action == GIFT_ACTION)
    best = None
    for name, pf in profiles.items():
        if pf["network"] != network or pf["account"] != account:
            continue
        is_gw = (pf["state"] == "giveaway")
        if is_gw == want_giveaway:
            best = (name, pf)
            break
        if best is None:
            best = (name, pf)
    if best is not None:
        name, pf = best
        pp = Path(os.path.expanduser(pf["policy_path"]))
        return name, pf, pp, _sha256_file(pp)
    if network == "mainnet":
        sys.exit(
            f"no signing profile binds account {account} on mainnet. "
            f"Define one in {PROFILES_PATH} (see profiles.example.json) — "
            f"mainnet proposals require a named profile.")
    # testnet/devnet adhoc: bind the default (or giveaway) policy digest
    pp = GIVEAWAY_POLICY_PATH if want_giveaway else POLICY_PATH
    if not pp.exists():
        sys.exit(f"proposal needs a policy file at {pp} — run "
                 f"`xrpl-sign init-policy` first")
    return "adhoc-testnet", None, pp, _sha256_file(pp)


# ---------- legacy seed detection (P1-2) ----------

def _looks_like_seed(v) -> bool:
    return isinstance(v, str) and v.startswith("s") and 28 <= len(v) <= 35


def detect_legacy_seeds():
    """Return [(path, description)] for seed material in legacy locations.

    Mainnet signing is BLOCKED while any are present — the operator must
    migrate (vault-only) first. Never deletes anything; migration is
    operator-driven.
    """
    found = []
    if CONFIG_PATH.exists():
        try:
            cfg = json.loads(CONFIG_PATH.read_text())
            if _looks_like_seed(cfg.get("seed")):
                found.append((str(CONFIG_PATH),
                              "config.json holds a seed (main-wallet seed)"))
        except (json.JSONDecodeError, OSError):
            pass
    if GIVEAWAY_PATH.exists():
        try:
            gw = json.loads(GIVEAWAY_PATH.read_text())
            if _looks_like_seed(gw.get("seed")):
                found.append((str(GIVEAWAY_PATH),
                              "giveaway.json holds the donation-wallet seed"))
        except (json.JSONDecodeError, OSError):
            pass
    for fp in XRPL_DIR.glob("faucet-*.json"):
        try:
            d = json.loads(fp.read_text())
            if _looks_like_seed(d.get("seed")):
                found.append((str(fp), "faucet file holds a testnet seed"))
        except (json.JSONDecodeError, OSError):
            pass
    return found


def block_mainnet_on_legacy_seeds():
    """P1-2: vault-only mainnet. Refuse mainnet signing while seed material
    sits in proposer-readable files, with migration guidance."""
    found = detect_legacy_seeds()
    # Faucet/testnet seeds are fine; only block on main-wallet material.
    blocking = [(p, d) for p, d in found if "faucet" not in p]
    if not blocking:
        return
    lines = ["MAINNET BLOCKED: seed material found in local files.",
             "Vault-only mainnet requires migrating these first — the signer",
             "will not read seeds from proposer-readable config on mainnet.",
             ""]
    for p, d in blocking:
        lines.append(f"  - {p}: {d}")
    lines += ["",
              "Migrate: store each seed in your password manager (the vault),",
              "then run `xrpl-trade wallet forget-seed --path <file>` to remove",
              "it from disk (after confirming the vault backup). Until then,",
              "mainnet signing stays blocked; testnet is unaffected."]
    sys.exit("\n".join(lines))


# Disabled-master-key honor (P1-1): a seed that derives to the account
# address itself is the MASTER seed. If the ledger shows lsfDisableMaster,
# that seed is dead — refuse, even though the signature would be rejected
# by the ledger anyway (fail closed, with a clear reason).
LSF_DISABLE_MASTER = 0x00100000


def check_ledger_key_authorization(client, account, derived_address):
    """Verify master/RegularKey authorization at a validated ledger."""
    from xrpl.models.requests import AccountInfo
    try:
        r = client.request(AccountInfo(account=account, ledger_index="validated"))
        if not r.is_successful() or r.result.get("validated") is not True:
            return "Could not verify validated signing authority"
        data = r.result["account_data"]
        if derived_address == account and not int(data.get("Flags", 0)) & LSF_DISABLE_MASTER:
            return None
        if derived_address == data.get("RegularKey"):
            return None
        return "Seed is not an enabled master key or authorized RegularKey"
    except Exception:
        return "Could not verify validated signing authority"



# ---------- safe terminal output ----------

def safe_terminal_text(s, limit=None):
    from xrpl_display import safe_terminal_text as sanitize
    return sanitize(s, limit)



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
        amt = tx.get("Amount")
        is_transfer = (is_sell and not owner and dest
                       and isinstance(amt, str) and amt == "0")
        if is_transfer:
            # A 0-drops sell offer aimed at a Destination is a GIFT
            # transfer — the ceremony must never describe it as a sale.
            lines += [f"token:    {tx.get('NFTokenID')}",
                      "action:   TRANSFER (gift — 0 XRP, NOT a sale)",
                      f"to:       {dest}",
                      "note:     recipient must accept before expiry — "
                      "nothing moves until they do"]
        else:
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
    return [safe_terminal_text(line) for line in lines]


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
        amt = tx.get("Amount")
        try:
            is_sell = bool(int(str(tx.get("Flags", 0))) & NFT_SELL_FLAG)
        except (ValueError, TypeError):
            is_sell = False
        if (is_sell and tx.get("Destination")
                and isinstance(amt, str) and amt == "0"):
            pass  # gift transfer (nft-send): 0 drops is the legitimate
            # amount. Shape enforcement (no Owner, valid destination)
            # lives in check_nft_offer + the envelope invariants.
        else:
            p = num(amt, "Amount")
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
                if bid <= 0:
                    denials.append("bid Amount must be positive — refusing")
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
        elif tx.get("Amount") == "0" and tx.get("Destination") is None:
            # 0-drops carve-out: a gift TRANSFER is allowed only as a sell
            # offer aimed at a Destination (nft-send). A 0-XRP offer with
            # no destination is a meaningless public listing — refused.
            denials.append(
                "0-XRP NFTokenCreateOffer without a Destination — "
                "refusing (use nft-send for transfers)")

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


def _require_validated_ledger(result, what):
    """Fail closed unless a ledger-data response came from a validated
    ledger. Peer servers default to their mutable current ledger; XRPL
    documentation recommends pinning reads to a validated one."""
    if not isinstance(result, dict) or result.get("validated") is not True:
        return (f"{what}: node returned data from an unvalidated ledger — "
                "refusing")
    return None


def fetch_nft_offer_entry(client, offer_index: str, ledger_index="validated"):
    """Fetch an NFTokenOffer ledger entry by its index. Returns
    (entry_dict, problem). problem is None on success. Fail closed:
    any lookup failure is a problem, never an assumption.

    Reads are pinned to a validated ledger (default: the latest validated
    one); callers verifying several facts pin them all to ONE validated
    ledger index so the facts can't come from different ledger states."""
    from xrpl.models.requests import LedgerEntry
    if not (isinstance(offer_index, str) and len(offer_index) == 64
            and all(c in "0123456789abcdefABCDEF" for c in offer_index)):
        return None, ("offer index must be 64 hex characters — refusing")
    try:
        r = client.request(LedgerEntry(index=offer_index.upper(),
                                       ledger_index=ledger_index))
    except Exception as e:  # noqa: BLE001
        return None, (f"could not read the offer from the ledger: {e} — "
                       f"refusing")
    if not r.is_successful():
        return None, (f"offer not on ledger (entryNotFound or node error) — "
                       f"refusing")
    res = r.result or {}
    problem = _require_validated_ledger(res, "offer lookup")
    if problem or (isinstance(ledger_index, int) and res.get("ledger_index") != ledger_index):
        return None, problem or "Offer ledger does not match pinned ledger"
    node = res.get("node")
    if not isinstance(node, dict):
        return None, "ledger returned a malformed offer entry — refusing"
    return node, None


def fetch_nft_meta(client, owner: str, nftoken_id: str,
                   ledger_index="validated"):
    """On-ledger NFT metadata (URI text, taxon, issuer) for one token.
    Returns (uri_text, taxon, issuer, problem). A missing token is a
    problem — this is the counterfeit check: the seller must actually
    own the token on the ledger right now.

    The issuer (minter) is distinct from the seller (current owner):
    anyone can mint the same artwork, so the human judges the issuer,
    never the seller.

    Reads are pinned to a validated ledger; see fetch_nft_offer_entry."""
    from xrpl.models.requests import AccountNFTs
    marker = None
    while True:
        try:
            r = client.request(AccountNFTs(account=owner, limit=400,
                                           ledger_index=ledger_index,
                                           marker=marker))
        except Exception as e:  # noqa: BLE001
            return None, None, None, (f"could not read the seller's NFTs: "
                                      f"{e} — refusing")
        if not r.is_successful():
            return None, None, None, ("could not read the seller's NFTs "
                                      "(node error) — refusing")
        res = r.result or {}
        problem = _require_validated_ledger(res, "NFT inventory lookup")
        if problem or (isinstance(ledger_index, int) and res.get("ledger_index") != ledger_index):
            return None, None, None, problem or "Inventory ledger does not match pinned ledger"
        for n in res.get("account_nfts", []):
            if n.get("NFTokenID") == nftoken_id:
                uri_hex = n.get("URI", "")
                try:
                    uri_txt = bytes.fromhex(uri_hex).decode("utf-8", "replace")
                except (ValueError, TypeError):
                    uri_txt = "<uri is not valid hex>"
                return (uri_txt, n.get("NFTokenTaxon"), n.get("Issuer"),
                        None)
        marker = res.get("marker")
        if not marker:
            break
    return None, None, None, ("token not found in the seller's inventory — "
                             "the seller may no longer own it — refusing")


def nft_sell_offer_report(client, offer_index: str):
    """Full verification of an NFT sell offer from the ledger.

    Returns (report_lines, denials, xrp_amount_or_None). The report is
    the anti-counterfeit ceremony: seller (current owner), issuer
    (minter), token id, price, on-ledger URI and taxon — facts for the
    human to judge, never an authenticity claim."""
    from xrpl.utils import drops_to_xrp
    lines = []
    # Pin the offer-entry and ownership checks to ONE validated ledger, so
    # the report can't mix facts from different ledger states.
    ledger_index, problem = get_validated_ledger(client)
    if problem:
        return [], [problem], None
    entry, problem = fetch_nft_offer_entry(client, offer_index, ledger_index)
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
    if not price.is_finite() or price < 0:
        return [], ["Invalid NFT offer amount"], None
    seller = entry.get("Owner", "?")
    nid = entry.get("NFTokenID", "?")
    uri_txt, taxon, issuer, meta_problem = fetch_nft_meta(
        client, seller, nid, ledger_index)
    lines.append(f"offer:    {offer_index.upper()}")
    lines.append(f"seller:   {seller} (current owner)")
    lines.append(f"issuer:   {issuer or '?'} (minter)")
    lines.append(f"token:    {nid}")
    lines.append(f"price:    {price} XRP")
    if meta_problem:
        return lines, [meta_problem], None
    lines.append(f"uri:      {safe_terminal_text(uri_txt, 120)}")
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


# ---------- assistant profile (onboarding) ----------

class ProfileError(Exception):
    """Profile file unreadable or from a newer skill version."""


# Membership / interest tags: lowercase, 1-40 chars.
PROFILE_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9 _-]{0,39}$")
# XRPL family seeds are base58 starting with 's' (secp256k1 ~29 chars,
# ed25519 'sEd…' longer). Classic addresses start with 'r' — a valid
# address never matches this.
SEED_LIKE_RE = re.compile(r"^s[1-9A-HJ-NP-Za-km-z]{27,60}$")
PROFILE_BOOL_TRUE = {"true", "yes", "y", "1", "on"}
PROFILE_BOOL_FALSE = {"false", "no", "n", "0", "off"}
# Conventional interest tags the assistant may suggest. Free-form tags
# are also accepted — this list only seeds suggestions.
SUGGESTED_INTERESTS = ["trading", "nfts", "dao-governance", "discovery",
                       "defi", "gaming"]


def looks_like_secret(s):
    """Heuristic: does this look like a wallet seed/secret, not an address?

    Never used to *detect* a real secret for storage — only to REFUSE
    one. False positives are safe (the user just retypes); a false
    negative still fails classic-address validation downstream.
    """
    if not isinstance(s, str):
        return False
    t = s.strip()
    if SEED_LIKE_RE.match(t):
        return True
    low = t.lower()
    return "seed" in low or "secret" in low


SEED_WARNING = (
    "STOP — that looks like a wallet SEED/secret, not an address. "
    "NEVER share your seed with anyone or anything, including this skill. "
    "Your watch-only XRPL address starts with 'r'. Nothing was saved."
)


def validate_watch_address(addr):
    """Returns a problem string, or None when the address is a usable
    watch-only classic address. Seed-like input gets the loud refusal."""
    if not isinstance(addr, str) or not addr.strip():
        return "address is empty"
    a = addr.strip()
    if looks_like_secret(a):
        return SEED_WARNING
    if not is_valid_classic_address(a):
        return ("address is not a valid classic address "
                "(base58 checksum failed) — it must start with 'r'")
    return None


def default_profile():
    now = int(time.time())
    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "display_name": "",
        "xrpl_addresses": [],
        "memberships": [],
        "interests": [],
        "alerts": {"price_moves": False, "threshold_pct": 3.0},
        "created_at": now,
        "updated_at": now,
        # giveaway: community opt-in state. Managed ONLY by the giveaway
        # opt-in flow — `opt_in` flips to true only after the 1-drop entry
        # payment is validated on-ledger, never at proposal time.
        "giveaway": {"opt_in": False, "opt_in_tx": None},
    }


def normalize_profile(prof):
    """Fill defaults for missing keys so `show` always renders the full
    shape. Returns the normalized dict (mutates the input)."""
    base = default_profile()
    for key, val in base.items():
        if key not in prof:
            prof[key] = val
    if not isinstance(prof.get("alerts"), dict):
        prof["alerts"] = {"price_moves": False, "threshold_pct": 3.0}
    else:
        for key, val in base["alerts"].items():
            if key not in prof["alerts"]:
                prof["alerts"][key] = val
    if not isinstance(prof.get("giveaway"), dict):
        prof["giveaway"] = {"opt_in": False, "opt_in_tx": None}
    else:
        # schema-v1 profiles written before the giveaway feature get the
        # default (not opted in); never let a stray key break readers.
        for key, val in base["giveaway"].items():
            if key not in prof["giveaway"]:
                prof["giveaway"][key] = val
    for key in ("xrpl_addresses", "memberships", "interests"):
        if not isinstance(prof.get(key), list):
            prof[key] = []
    return prof


def load_profile(path=None):
    """Load the assistant profile. {} when absent (not onboarded yet).
    Raises ProfileError on corrupt JSON or a newer schema — fail loud,
    never silently empty."""
    p = Path(path) if path else PROFILE_PATH
    if not p.exists():
        return {}
    try:
        prof = json.loads(p.read_text())
    except (json.JSONDecodeError, OSError) as e:
        raise ProfileError(
            f"profile file is unreadable ({p}): {e} — fix or delete it")
    if not isinstance(prof, dict):
        raise ProfileError(f"profile file is not a JSON object ({p})")
    ver = prof.get("schema_version", 1)
    if ver > PROFILE_SCHEMA_VERSION:
        raise ProfileError(
            f"profile schema v{ver} is newer than this skill "
            f"(v{PROFILE_SCHEMA_VERSION}) — upgrade the skill")
    return normalize_profile(prof)


def save_profile(prof, path=None):
    """Persist the profile atomically, owner-only 0600. Stamps updated_at."""
    p = Path(path) if path else PROFILE_PATH
    prof = dict(prof)
    prof["schema_version"] = PROFILE_SCHEMA_VERSION
    prof["updated_at"] = int(time.time())
    if "created_at" not in prof:
        prof["created_at"] = prof["updated_at"]
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(prof, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def set_profile_field(prof, field, value):
    """Set a scalar profile field. Returns a problem string, or None."""
    if field == "display_name":
        name = (value or "").strip()
        if not name:
            return "display_name must not be empty"
        if len(name) > 40:
            return "display_name is too long (max 40 chars)"
        prof["display_name"] = name
        return None
    if field == "alerts.price_moves":
        v = (value or "").strip().lower()
        if v in PROFILE_BOOL_TRUE:
            prof["alerts"]["price_moves"] = True
            return None
        if v in PROFILE_BOOL_FALSE:
            prof["alerts"]["price_moves"] = False
            return None
        return (f"alerts.price_moves must be true/false (got {value!r})")
    if field == "alerts.threshold_pct":
        try:
            pct = float(value)
        except (TypeError, ValueError):
            return (f"alerts.threshold_pct must be a number (got {value!r})")
        if not 0.5 <= pct <= 50:
            return "alerts.threshold_pct must be between 0.5 and 50"
        prof["alerts"]["threshold_pct"] = pct
        return None
    return (f"unknown profile field {field!r} — settable: display_name, "
            "alerts.price_moves, alerts.threshold_pct "
            "(addresses/memberships/interests use add-*/remove-*)")


def normalize_tag(name):
    """Lowercase/strip a membership or interest tag. Returns (tag, problem)."""
    if not isinstance(name, str):
        return None, "tag must be text"
    tag = name.strip().lower()
    if not PROFILE_TAG_RE.match(tag):
        return None, (f"tag {name!r} is invalid — use 1-40 chars: lowercase "
                       "letters, digits, space, '-' or '_'")
    return tag, None


def add_profile_list_item(prof, key, value):
    """Add to xrpl_addresses/memberships/interests. Returns problem or None."""
    if key == "xrpl_addresses":
        problem = validate_watch_address(value)
        if problem:
            return problem
        addr = value.strip()
        if addr in prof["xrpl_addresses"]:
            return f"address {addr} is already in your profile"
        prof["xrpl_addresses"].append(addr)
        return None
    tag, problem = normalize_tag(value)
    if problem:
        return problem
    if tag in prof[key]:
        return f"{key[:-1]} {tag!r} is already in your profile"
    prof[key].append(tag)
    return None


def remove_profile_list_item(prof, key, value):
    """Remove from xrpl_addresses/memberships/interests. Returns problem/None."""
    if key == "xrpl_addresses":
        addr = (value or "").strip()
        if addr not in prof["xrpl_addresses"]:
            return f"address {addr} is not in your profile"
        prof["xrpl_addresses"].remove(addr)
        return None
    tag = (value or "").strip().lower()
    if tag not in prof[key]:
        return f"{key[:-1]} {tag!r} is not in your profile"
    prof[key].remove(tag)
    return None


# ---------- friday community giveaway ----------
#
# Design: anyone can donate to the donation wallet; entrants opt in with a
# single 1-drop (0.000001 XRP) Payment to the donation wallet carrying the
# opt-in destination tag. One marker-paged account_tx scan of the donation
# wallet finds every entrant — no server, no registration list. The Friday
# draw selects a winner deterministically from a FUTURE ledger hash, so the
# outcome is independently verifiable by anyone. The draw only SELECTS; it
# never builds or submits a gift transaction (that stays human-approved).
#
# The donation wallet below ("Musegives") is public by design — publishing
# it is how people find the pot. Never put a seed anywhere near this file.

GIVEAWAY_PATH = XRPL_DIR / "giveaway.json"
GIVEAWAY_SCHEMA_VERSION = 1
DEFAULT_DONATION_WALLET = "rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB"  # "Musegives"
DEFAULT_OPT_IN_TAG = 777
OPT_IN_DROPS = "1"  # exactly 1 drop = 0.000001 XRP

# P2: the gift path. The donation wallet's seed is read ONLY from the
# XRPL_GIVEAWAY_SEED environment variable (vault-injected in production,
# exactly like XRPL_SEED). Local testnet credentials live in a separate,
# network-tagged file and are never read by the signing credential path.
GIVEAWAY_SEED_ENV = "XRPL_GIVEAWAY_SEED"
GIVEAWAY_POLICY_PATH = XRPL_DIR / "giveaway_policy.json"
GIVEAWAY_STATE_PATH = XRPL_DIR / "giveaway_state.json"
GIVEAWAY_STATE_LOCK_PATH = XRPL_DIR / "giveaway_state.lock"
GIVEAWAY_LAST_DRAW_PATH = XRPL_DIR / "giveaway_last_draw.json"
GIFT_ACTION = "giveaway-gift"
DEFAULT_MAX_GIFT_XRP = "10"  # per-gift XRP cap; raise deliberately, not by accident

# Transaction types that count as "wallet activity" for giveaway eligibility.
# The 1-drop opt-in Payment itself is explicitly NOT activity.
WALLET_ACTION_TYPES = {
    "Payment",            # any payment that is not the opt-in itself
    "OfferCreate",
    "OfferCancel",
    "TrustSet",
    "NFTokenMint",
    "NFTokenCreateOffer",
    "NFTokenAcceptOffer",
    "NFTokenCancelOffer",
}


def default_giveaway_config():
    return {
        "schema_version": GIVEAWAY_SCHEMA_VERSION,
        "donation_wallet": DEFAULT_DONATION_WALLET,
        "opt_in_tag": DEFAULT_OPT_IN_TAG,
        "max_gift_xrp": DEFAULT_MAX_GIFT_XRP,
        "network": "mainnet",
    }


def ensure_giveaway_config():
    """Write ~/.xrpl/giveaway.json with defaults when missing (owner-only
    0600, atomic)."""
    if not GIVEAWAY_PATH.exists():
        GIVEAWAY_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = GIVEAWAY_PATH.with_name(GIVEAWAY_PATH.name + ".tmp")
        tmp.write_text(json.dumps(default_giveaway_config(), indent=2,
                                  sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, GIVEAWAY_PATH)


def load_giveaway_config(donation_wallet_override=None):
    """Config for the giveaway commands. `--donation-wallet r…` lets any
    community leader point the same machinery at their own wallet with no
    code changes. Exits on an invalid wallet/tag — an invalid config must
    never silently scan the wrong wallet."""
    ensure_giveaway_config()
    try:
        raw = json.loads(GIVEAWAY_PATH.read_text())
    except (json.JSONDecodeError, OSError) as e:
        sys.exit(f"giveaway: {GIVEAWAY_PATH} is unreadable: {e}")
    if not isinstance(raw, dict):
        sys.exit(f"giveaway: {GIVEAWAY_PATH} is not a JSON object")
    cfg = default_giveaway_config()
    cfg.update(raw)
    if donation_wallet_override:
        wallet = donation_wallet_override.strip()
        if not is_valid_classic_address(wallet):
            sys.exit(f"giveaway: --donation-wallet {wallet!r} is not a "
                     f"valid classic address")
        cfg["donation_wallet"] = wallet
    wallet = cfg.get("donation_wallet", "")
    if not is_valid_classic_address(wallet):
        sys.exit(f"giveaway: donation_wallet {wallet!r} in {GIVEAWAY_PATH} "
                 f"is not a valid classic address — fix the file")
    tag = cfg.get("opt_in_tag", DEFAULT_OPT_IN_TAG)
    if not isinstance(tag, int) or not (0 <= tag <= 0xFFFFFFFF):
        sys.exit(f"giveaway: opt_in_tag {tag!r} in {GIVEAWAY_PATH} must be "
                 f"an integer 0..4294967295")
    cfg["donation_wallet"] = wallet
    cfg["opt_in_tag"] = tag
    mgx = cfg.get("max_gift_xrp", DEFAULT_MAX_GIFT_XRP)
    try:
        mgx_d = Decimal(str(mgx))
    except Exception:  # noqa: BLE001
        sys.exit(f"giveaway: max_gift_xrp {mgx!r} in {GIVEAWAY_PATH} "
                 f"is not a number")
    if not mgx_d.is_finite() or mgx_d <= 0:
        sys.exit(f"giveaway: max_gift_xrp {mgx!r} in {GIVEAWAY_PATH} "
                 f"must be a positive number")
    cfg["max_gift_xrp"] = mgx_d
    net = cfg.get("network", "mainnet")
    if net not in NETWORKS:
        sys.exit(f"giveaway: network {net!r} in {GIVEAWAY_PATH} is not one of "
                 f"{sorted(NETWORKS)}")
    cfg["network"] = net
    return cfg


def is_opt_in_payment(entry, donation_wallet, opt_in_tag):
    """Pure check: is this account_tx entry a valid giveaway opt-in?

    All five must hold: validated, Payment, FROM someone else (never the
    donation wallet paying itself), TO the donation wallet, exactly
    OPT_IN_DROPS with the exact opt-in destination tag, successful result.
    """
    if not entry.get("validated"):
        return False
    tx = entry.get("tx") or {}
    if tx.get("TransactionType") != "Payment":
        return False
    meta = entry.get("meta") or entry.get("metaData") or {}
    if meta.get("TransactionResult") != "tesSUCCESS":
        return False
    if tx.get("Account") == donation_wallet:
        return False
    if tx.get("Destination") != donation_wallet:
        return False
    if tx.get("DestinationTag") != opt_in_tag:
        return False
    if str(tx.get("Amount")) != OPT_IN_DROPS:
        return False
    return True


def _account_tx_all(client, account, page_limit=200, max_pages=25):
    """Marker-page account_tx, newest first. Returns (entries, problem)."""
    from xrpl.models.requests import AccountTx
    entries, marker, pages = [], None, 0
    while True:
        kw = {"account": account, "limit": page_limit}
        if marker is not None:
            kw["marker"] = marker
        try:
            resp = client.request(AccountTx(**kw))
        except Exception as e:
            return None, f"account_tx for {account[:10]}… failed: {e}"
        if not resp.is_successful():
            return None, (f"account_tx for {account[:10]}… failed: "
                          f"{(resp.result or {}).get('error', resp.result)}")
        res = resp.result or {}
        entries.extend(res.get("transactions") or [])
        marker = res.get("marker")
        pages += 1
        if not marker or pages >= max_pages:
            break
    return entries, None


def scan_opt_ins(client, donation_wallet, opt_in_tag):
    """Scan the donation wallet's incoming txs for valid opt-ins.
    Returns ({address: earliest_opt_in_hash}, problem)."""
    entries, problem = _account_tx_all(client, donation_wallet)
    if problem:
        return None, problem
    found = {}
    for entry in entries:
        if is_opt_in_payment(entry, donation_wallet, opt_in_tag):
            # newest-first scan: later overwrites keep the earliest tx.
            found[entry["tx"]["Account"]] = entry.get("hash")
    return found, None


def find_opt_in_tx(client, account, donation_wallet, opt_in_tag):
    """The account's own opt-in payment to the donation wallet, if any.
    Returns (hash | None, problem). Scans the account's history, so the
    donation wallet doesn't even need to have received it yet."""
    entries, problem = _account_tx_all(client, account, max_pages=10)
    if problem:
        return None, problem
    best = None
    for entry in reversed(entries):  # oldest first -> keep the earliest
        if is_opt_in_payment(entry, donation_wallet, opt_in_tag) \
                and entry["tx"]["Account"] == account:
            if best is None:
                best = entry.get("hash")
    return best, None


def count_wallet_actions(client, account, exclude_hashes=()):
    """Count the account's qualifying wallet actions (opt-in txs excluded).
    Returns (count, problem). Only successful, validated txs count."""
    excluded = set(exclude_hashes or ())
    entries, problem = _account_tx_all(client, account, max_pages=10)
    if problem:
        return None, problem
    n = 0
    for entry in entries:
        if entry.get("hash") in excluded:
            continue
        if not entry.get("validated"):
            continue
        meta = entry.get("meta") or entry.get("metaData") or {}
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue
        tx = entry.get("tx") or {}
        if tx.get("Account") != account:
            continue  # inbound noise (e.g. someone paying them) isn't activity
        if tx.get("TransactionType") in WALLET_ACTION_TYPES:
            n += 1
    return n, None


def eligible_entrants(client, donation_wallet, opt_in_tag):
    """Everyone who opted in, annotated with eligibility.
    Returns (list of {address, opt_in_tx, action_count, eligible}, problem).
    Sorted by address so the draw order is canonical."""
    opt_ins, problem = scan_opt_ins(client, donation_wallet, opt_in_tag)
    if problem:
        return None, problem
    entrants = []
    for address in sorted(opt_ins):
        opt_in_hash = opt_ins[address]
        actions, problem = count_wallet_actions(client, address,
                                                exclude_hashes=(opt_in_hash,))
        if problem:
            return None, problem
        entrants.append({
            "address": address,
            "opt_in_tx": opt_in_hash,
            "action_count": actions,
            "eligible": actions >= 1,
        })
    return entrants, None


def pick_giveaway_winner(eligible, ledger_hash):
    """Pure, deterministic draw. `eligible` is the sorted-by-address list of
    {address, opt_in_tx} dicts (exactly as eligible_entrants returns).
    seed = ledger_hash + ":" + comma-joined opt-in hashes in address order;
    index = sha256(seed) mod len(eligible).
    Returns (index, digest_hex, seed_string). Raises on empty input."""
    if not eligible:
        raise ValueError("pick_giveaway_winner: no eligible entrants")
    ordered = sorted(eligible, key=lambda e: e["address"])
    seed = ledger_hash + ":" + ",".join(e["opt_in_tx"] for e in ordered)
    digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return int(digest, 16) % len(ordered), digest, seed


def wait_for_ledger_hash(client, target_index, timeout=600, poll=5):
    """Wait until target_index is validated, then return its hash.
    Returns (ledger_hash, problem). The draw uses a FUTURE ledger hash so
    the outcome can't be known (or rigged) before the drawing time."""
    from xrpl.models.requests import Ledger
    deadline = time.time() + timeout
    while True:
        idx, problem = get_validated_ledger(client)
        if problem:
            return None, problem
        if idx >= target_index:
            break
        if time.time() > deadline:
            return None, (f"timed out waiting for ledger {target_index} "
                          f"(validated at {idx})")
        time.sleep(poll)
    try:
        resp = client.request(Ledger(ledger_index=target_index))
    except Exception as e:
        return None, f"ledger {target_index} fetch failed: {e}"
    if not resp.is_successful():
        return None, (f"ledger {target_index} fetch failed: "
                      f"{(resp.result or {}).get('error', resp.result)}")
    res = resp.result or {}
    h = res.get("ledger_hash") or (res.get("ledger") or {}).get("ledger_hash")
    if not h:
        return None, f"ledger {target_index} response had no hash"
    return h, None


# ---------- giveaway gifts (P2) ----------
#
# `giveaway gift` PROPOSES a prize payment from the donation wallet. It is
# proposed exactly like any other write (full ceremony, hash-bound
# envelope) and signed only after independent human approval of that
# exact hash — there is no auto-send path anywhere in this flow.
#
# Signing uses the donation wallet's OWN key under the giveaway policy
# (~/.xrpl/giveaway_policy.json), not the main wallet's policy:
#   xrpl-sign --hash <h> --approve \
#       --seed-env XRPL_GIVEAWAY_SEED --policy ~/.xrpl/giveaway_policy.json
# The vault injects XRPL_GIVEAWAY_SEED after human approval (same pattern
# as XRPL_SEED); local giveaway seed storage is testnet-only and is not a
# signing fallback.

def check_payment_destination(tx, policy):
    """Denial reasons for a Payment's destination (pure — no network).

    Default: exact (address, destination-tag) allowlist match. Giveaway
    mode (`allow_any_payment_destination`): winners are arbitrary
    addresses — the human approved this exact destination in the proposal
    ceremony, so the signer only re-validates the shape (valid classic
    address, never seed-like)."""
    denials = []
    dest, tag = tx.get("Destination", ""), tx.get("DestinationTag")
    if policy.get("allow_any_payment_destination"):
        if not is_valid_classic_address(dest):
            denials.append(
                f"destination {dest!r} is not a valid classic address")
        elif looks_like_secret(dest):
            denials.append("destination looks like a seed/secret — refusing")
        return denials
    allowlist = policy.get("destination_allowlist", [])
    ok = any(e.get("address") == dest and e.get("destination_tag") == tag
             for e in allowlist)
    if not ok:
        denials.append(
            f"destination ({str(dest)[:12]}…, tag {tag}) not in "
            f"destination_allowlist ({len(allowlist)} entries)")
    return denials


def validate_gift_destination(to, donation_wallet):
    """Problem string, or None when `to` is a usable gift destination.

    Seed-like input gets the loud STOP refusal (same as profile
    add-address); anything that isn't a valid classic address is refused;
    the donation wallet itself is refused (a gift to yourself is pointless).
    """
    if not isinstance(to, str) or not to.strip():
        return "winner address is empty"
    t = to.strip()
    if looks_like_secret(t):
        return SEED_WARNING
    if not is_valid_classic_address(t):
        return ("winner address is not a valid classic address "
                "(base58 checksum failed) — it must start with 'r'")
    if t == donation_wallet:
        return ("winner is the donation wallet itself — "
                "a gift to yourself is pointless")
    return None


def check_gift_cap(amount: Decimal, ccy: str, max_gift_xrp: Decimal):
    """Refuse XRP gifts above the deliberate per-gift cap.

    IOU gifts are NOT comparable to an XRP cap without a price feed, so
    they are bounded instead by the giveaway policy's per-asset
    spend_limits, enforced fail-closed by the signer at signing time.
    """
    if ccy == "XRP" and amount > max_gift_xrp:
        return (f"gift of {amount} XRP exceeds max_gift_xrp={max_gift_xrp} — "
                f"raise the cap deliberately in {GIVEAWAY_PATH} (and the "
                f"giveaway policy's XRP per-tx limit) if you mean it")
    return None


def require_local_network(network):
    if network not in ("testnet", "devnet"):
        sys.exit("Mainnet is vault-only: explicit testnet/devnet identity required for local credentials")


def local_wallet_path(network):
    require_local_network(network)
    return XRPL_DIR / ("local-wallet-" + network + ".json")


def read_giveaway_seed():
    """Legacy disk-seed fallback is intentionally disabled on all networks."""
    return None


def write_giveaway_seed(seed, network=None):
    require_local_network(network)
    """Atomically store the seed in giveaway.json (owner-only 0600).

    Called ONLY by the interactive `giveaway setup` (getpass, never
    echoed). Never prints the seed."""
    from xrpl.wallet import Wallet
    address = Wallet.from_seed(seed).classic_address
    atomic_private_json(XRPL_DIR / ("local-giveaway-" + network + ".json"),
                        {"format": "xrpl-local-test-wallet/1", "network": network,
                         "address": address, "seed": seed})



def default_giveaway_policy(max_gift_xrp, network):
    """The signer policy for donation-wallet gifts. Written once by
    `giveaway setup`; the leader edits it directly after that.

    Deliberately narrow: only Payment and NFTokenCreateOffer, only the
    giveaway network. Destinations are NOT allowlisted (winners are
    arbitrary addresses) — the human approves each exact destination in
    the proposal ceremony, the signer re-validates the address shape, and
    max_gift_xrp bounds every XRP gift."""
    mgx = str(max_gift_xrp)
    return {
        "policy_version": POLICY_VERSION,
        "giveaway": True,
        "network_lock": network,
        "allowed_tx_types": ["Payment", "NFTokenCreateOffer"],
        "allow_any_payment_destination": True,
        "max_fee_drops": 100,
        "spend_limits": {
            "XRP": {"per_tx": mgx, "per_day": str(Decimal(mgx) * 2)},
        },
        "destination_allowlist": [],
        "max_deviation_bps": 1000,
        "max_spread_bps": 1000,
        "min_book_depth": "5",
        "max_offer_lifetime_seconds": 86400,
        "proposal_ttl_seconds": 86400,
        "nft": json.loads(json.dumps(DEFAULT_POLICY["nft"])),
    }


def write_giveaway_policy(max_gift_xrp, network):
    """Write ~/.xrpl/giveaway_policy.json (0600, atomic). Refuses to
    overwrite an existing policy — the leader edits it directly."""
    if GIVEAWAY_POLICY_PATH.exists():
        return False
    GIVEAWAY_POLICY_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = GIVEAWAY_POLICY_PATH.with_name(GIVEAWAY_POLICY_PATH.name + ".tmp")
    tmp.write_text(json.dumps(default_giveaway_policy(max_gift_xrp, network),
                              indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, GIVEAWAY_POLICY_PATH)
    return True


def giveaway_sign_command(proposal_hash, profile_name="adhoc-testnet"):
    """The exact signer invocation for a giveaway-gift proposal."""
    if profile_name == "adhoc-testnet":
        return (f"xrpl-sign --hash {proposal_hash} --approve "
                f"--seed-env {GIVEAWAY_SEED_ENV} --policy {GIVEAWAY_POLICY_PATH}")
    return (f"xrpl-sign --profile {profile_name} "
            f"--hash {proposal_hash} --approve")


def save_last_draw(record):
    """Persist the public draw result for `giveaway announce` (0600,
    atomic). No secrets — the draw is public by design."""
    GIVEAWAY_LAST_DRAW_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = GIVEAWAY_LAST_DRAW_PATH.with_name(
        GIVEAWAY_LAST_DRAW_PATH.name + ".tmp")
    tmp.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, GIVEAWAY_LAST_DRAW_PATH)


def load_last_draw():
    """Return the last draw record dict, or None when no draw is on record."""
    try:
        raw = json.loads(GIVEAWAY_LAST_DRAW_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return raw if isinstance(raw, dict) else None


def add_destination_allowlist_entry(address, destination_tag):
    """Add an exact (address, destination_tag) pair to ~/.xrpl/policy.json's
    destination_allowlist. Owner-only 0600, atomic. No duplicates.
    Returns a problem string, or None on success. Never exits: the caller
    (the opt-in flow) turns problems into text so onboarding can't be
    derailed."""
    try:
        policy = load_policy()
    except SystemExit as e:
        return str(e)  # e.g. "No policy file. Run `xrpl-sign init-policy`…"
    entry = {"address": address, "destination_tag": destination_tag}
    for existing in policy.get("destination_allowlist", []):
        if (existing.get("address") == address
                and existing.get("destination_tag") == destination_tag):
            return None  # already there
    policy.setdefault("destination_allowlist", []).append(entry)
    tmp = POLICY_PATH.with_name(POLICY_PATH.name + ".tmp")
    tmp.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, POLICY_PATH)
    return None


def decode_nft_uri(uri_hex, limit=90):
    """Hex-decode an NFToken URI for display. Never raises. Output is
    terminal-sanitized (see safe_terminal_text)."""
    try:
        txt = bytes.fromhex(uri_hex or "").decode("utf-8", "replace")
    except (ValueError, TypeError):
        return "<uri is not valid hex>"
    return safe_terminal_text(txt, limit)


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
    if type(idx) is not int or idx < 1 or r.result.get("validated") is not True:
        return None, "validated ledger response lacked a validated ledger_index"
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


class PolicyError(ValueError):
    """The policy file violates the strict schema. The signer and the
    trade CLI refuse to run against it — a malformed policy must never
    silently degrade into permissive defaults."""


# Sanity bounds for the strict policy schema. These are not trading
# opinions; they catch typos and smuggled absurdity (a "max fee" of
# ten billion drops is never what the operator meant).
_POLICY_MAX_MONEY = Decimal("1000000000000000")  # 1e15, any denomination
_POLICY_MAX_SECONDS = 10 * 365 * 86400           # 10 years
_POLICY_MAX_FEE_DROPS = 1_000_000
_POLICY_MAX_MINTS_PER_DAY = 1_000_000
_POLICY_MAX_URI_BYTES = 4096
_NFT_MINT_FLAG_BITS = {1, 2, 4, 8}  # burnable, only-xrp, trustline, transferable
_NFT_KNOWN_KEYS = {"max_transfer_fee", "max_mints_per_day",
                   "allowed_mint_flags", "max_uri_bytes",
                   "allow_buy_offers", "max_bid_xrp"}
# Giveaway-variant keys (see default_giveaway_policy): known, optional,
# strictly boolean. Anything else unknown is refused.
_POLICY_OPTIONAL_KEYS = {"giveaway", "allow_any_payment_destination"}
_POLICY_REQUIRED_KEYS = (set(DEFAULT_POLICY) - _POLICY_OPTIONAL_KEYS)


def _policy_int(v):
    """A real JSON integer (bool is not an integer here)."""
    return isinstance(v, int) and not isinstance(v, bool)


def _policy_decimal(v):
    """Decimal from a strict money value: str or int, never float (which
    would smuggle binary rounding into limit comparisons) or bool."""
    if isinstance(v, bool) or isinstance(v, float):
        return None
    try:
        d = Decimal(str(v))
        return d if d.is_finite() else None
    except (InvalidOperation, ValueError, TypeError):
        return None


def validate_policy(pol):
    """Strict schema validation for a MERGED policy (defaults already
    applied by load_policy). Returns pol unchanged on success.

    Raises PolicyError listing EVERY violation in one fail-closed error:
    unknown keys, wrong types, out-of-range values, bad addresses,
    unsupported networks or transaction types, and inconsistent NFT
    controls. Unknown keys are refused outright — a half-written
    value-policy field (e.g. a lone `allowed_nft_issuers`) must never be
    silently ignored."""
    from xrpl.core.addresscodec import is_valid_classic_address

    problems = []
    if not isinstance(pol, dict):
        raise PolicyError(
            "policy schema violation: policy must be a JSON object")

    for key in pol:
        if key not in _POLICY_REQUIRED_KEYS | _POLICY_OPTIONAL_KEYS:
            problems.append(f"unknown policy key {key!r}")
    for key in _POLICY_REQUIRED_KEYS:
        if key not in pol:
            problems.append(f"missing required policy key {key!r}")

    def _bad(cond, msg):
        if cond:
            problems.append(msg)

    if "policy_version" in pol:
        _bad(not _policy_int(pol["policy_version"])
             or pol["policy_version"] != POLICY_VERSION,
             f"policy_version must be {POLICY_VERSION}, "
             f"got {pol['policy_version']!r}")

    if "network_lock" in pol:
        _bad(not isinstance(pol["network_lock"], str)
             or pol["network_lock"] not in NETWORKS,
             f"network_lock must be one of {sorted(NETWORKS)}, "
             f"got {pol['network_lock']!r}")

    if "max_fee_drops" in pol:
        v = pol["max_fee_drops"]
        _bad(not _policy_int(v) or not 0 < v <= _POLICY_MAX_FEE_DROPS,
             f"max_fee_drops must be an integer 1..{_POLICY_MAX_FEE_DROPS}, "
             f"got {v!r}")

    if "spend_limits" in pol:
        lim = pol["spend_limits"]
        if not isinstance(lim, dict):
            problems.append("spend_limits must be an object of asset "
                            f"limits, got {lim!r}")
        else:
            for asset, entry in lim.items():
                where = f"spend_limits[{asset!r}]"
                _bad(not isinstance(asset, str) or not asset,
                     f"{where}: asset code must be a non-empty string")
                if not isinstance(entry, dict):
                    problems.append(f"{where} must be an object")
                    continue
                for k in entry:
                    if k not in ("per_tx", "per_day"):
                        problems.append(f"{where}: unknown key {k!r}")
                for k in ("per_tx", "per_day"):
                    d = _policy_decimal(entry.get(k))
                    _bad(d is None or d < 0 or d > _POLICY_MAX_MONEY,
                         f"{where}.{k} must be a non-negative decimal, "
                         f"got {entry.get(k)!r}")

    if "destination_allowlist" in pol:
        allow = pol["destination_allowlist"]
        if not isinstance(allow, list):
            problems.append("destination_allowlist must be a list, "
                            f"got {allow!r}")
        else:
            for i, entry in enumerate(allow):
                where = f"destination_allowlist[{i}]"
                if not isinstance(entry, dict):
                    problems.append(f"{where} must be an object")
                    continue
                for k in entry:
                    if k not in ("address", "destination_tag"):
                        problems.append(f"{where}: unknown key {k!r}")
                addr = entry.get("address")
                _bad(not isinstance(addr, str)
                     or not is_valid_classic_address(addr),
                     f"{where}.address is not a valid classic address: "
                     f"{addr!r}")
                tag = entry.get("destination_tag")
                _bad(tag is not None
                     and (not _policy_int(tag) or not 0 <= tag < 2 ** 32),
                     f"{where}.destination_tag must be null or an integer "
                     f"0..{2 ** 32 - 1}, got {tag!r}")

    for key in ("max_deviation_bps", "max_spread_bps"):
        if key in pol:
            v = pol[key]
            _bad(not _policy_int(v) or not 0 <= v <= 10_000,
                 f"{key} must be an integer 0..10000, got {v!r}")

    if "min_book_depth" in pol:
        d = _policy_decimal(pol["min_book_depth"])
        _bad(d is None or d < 0 or d > _POLICY_MAX_MONEY,
             "min_book_depth must be a non-negative decimal, "
             f"got {pol['min_book_depth']!r}")

    for key in ("max_offer_lifetime_seconds", "proposal_ttl_seconds"):
        if key in pol:
            v = pol[key]
            _bad(not _policy_int(v) or not 0 < v <= _POLICY_MAX_SECONDS,
                 f"{key} must be a positive integer of seconds, got {v!r}")

    if "allowed_tx_types" in pol:
        types = pol["allowed_tx_types"]
        supported = set(REQUIRED_FIELDS)
        if not isinstance(types, list):
            problems.append("allowed_tx_types must be a list, "
                            f"got {types!r}")
        else:
            for t in types:
                _bad(not isinstance(t, str) or t not in supported,
                     f"allowed_tx_types has unsupported transaction type "
                     f"{t!r} (supported: {sorted(supported)})")

    if "nft" in pol:
        nft = pol["nft"]
        if not isinstance(nft, dict):
            problems.append(f"nft must be an object, got {nft!r}")
        else:
            for k in nft:
                if k not in _NFT_KNOWN_KEYS:
                    problems.append(f"nft: unknown key {k!r}")
            v = nft.get("max_transfer_fee")
            _bad(not _policy_int(v) or not 0 <= v <= 50_000,
                 f"nft.max_transfer_fee must be an integer 0..50000, "
                 f"got {v!r}")
            v = nft.get("max_mints_per_day")
            _bad(not _policy_int(v) or not 0 <= v <= _POLICY_MAX_MINTS_PER_DAY,
                 "nft.max_mints_per_day must be a non-negative integer, "
                 f"got {v!r}")
            flags = nft.get("allowed_mint_flags")
            if not isinstance(flags, list) or any(
                    not _policy_int(f) or f not in _NFT_MINT_FLAG_BITS
                    for f in flags):
                problems.append(
                    "nft.allowed_mint_flags must be a list of flag bits "
                    f"{sorted(_NFT_MINT_FLAG_BITS)}, got {flags!r}")
            v = nft.get("max_uri_bytes")
            _bad(not _policy_int(v) or not 0 < v <= _POLICY_MAX_URI_BYTES,
                 "nft.max_uri_bytes must be a positive integer "
                 f"<= {_POLICY_MAX_URI_BYTES}, got {v!r}")
            _bad(not isinstance(nft.get("allow_buy_offers"), bool),
                 "nft.allow_buy_offers must be true/false, "
                 f"got {nft.get('allow_buy_offers')!r}")
            d = _policy_decimal(nft.get("max_bid_xrp"))
            _bad(d is None or d < 0 or d > _POLICY_MAX_MONEY,
                 "nft.max_bid_xrp must be a non-negative decimal, "
                 f"got {nft.get('max_bid_xrp')!r}")
            # NOTE: no allow_buy_offers/allowed_tx_types consistency rule
            # here on purpose: allow_buy_offers also gates *bids*
            # (NFTokenCreateOffer, in the defaults), so an operator who
            # allows bids but not accepts is coherent. The parked
            # value-policy fields are enforced by unknown-key rejection
            # above — a lone allowed_nft_issuers can never slip through.

    for key in _POLICY_OPTIONAL_KEYS:
        if key in pol:
            _bad(not isinstance(pol[key], bool),
                 f"{key} must be true/false, got {pol[key]!r}")

    if problems:
        raise PolicyError("policy schema violation:\n  "
                          + "\n  ".join(problems))
    return pol


def load_policy(path=None, expected_digest=None):
    p = Path(path) if path else POLICY_PATH
    if not p.exists():
        sys.exit(f"No policy file. Run `xrpl-sign init-policy` first ({p}).")
    try:
        raw = p.read_bytes()
        if expected_digest is not None and hashlib.sha256(raw).hexdigest() != expected_digest:
            sys.exit("Policy changed since approval; rebuild the proposal")
        pol = json.loads(raw)
    except json.JSONDecodeError:
        sys.exit(f"Policy file is not valid JSON: {p}")
    if not isinstance(pol, dict):
        sys.exit("Policy must be a JSON object")
    if pol.get("policy_version") != POLICY_VERSION:
        sys.exit(f"Policy is v{pol.get('policy_version')}, signer requires "
                 f"v{POLICY_VERSION} — run `xrpl-sign migrate-policy`.")
    merged = dict(DEFAULT_POLICY)
    merged.update(pol)
    try:
        return validate_policy(merged)
    except PolicyError as e:
        sys.exit(str(e))


def check_protected_files(extra=()):
    """Fail closed unless signer state is owner-only.

    The protected deployment boundary is: the xrpl-sign program itself,
    policy.json, approved.json, favorites.json, state.json, state.lock,
    audit.log. (The
    binary is a deployment concern — documented in SECURITY.md.) If the
    agent can rewrite policy or delete state, daily limits are fiction.
    Proposals stay agent-writable: they are treated as hostile input and
    fully verified.

    `extra` adds more protected paths (giveaway mode: the giveaway policy
    and giveaway.json, which may hold the donation-wallet seed).
    """
    problems = []
    try:
        euid = os.geteuid()
    except AttributeError:
        return  # non-POSIX: deployment must protect these another way
    # `extra` covers giveaway-mode files: the giveaway policy and
    # giveaway.json (which may hold the donation-wallet seed).
    for p in (POLICY_PATH, PROFILES_PATH, APPROVED_PATH, FAVORITES_PATH,
              STATE_PATH, STATE_LOCK_PATH, GIVEAWAY_STATE_PATH,
              GIVEAWAY_STATE_LOCK_PATH, AUDIT_PATH, *extra):
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

def atomic_private_json(path, data):
    import tempfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".xrpl-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            os.chmod(name, 0o600)
            json.dump(data, out, allow_nan=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
        if os.name == "posix":
            dfd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class StateCorruptError(Exception):
    """Accounting is unavailable; never infer an empty budget."""


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

    class StateError(StateCorruptError):
        """Spend state is corrupt or unreadable — fail closed, recover."""

    @staticmethod
    def _validate_entry(e):
        if not isinstance(e, dict):
            raise SpentTracker.StateError("State entry must be an object")
        for field in ("rid", "asset"):
            if not isinstance(e.get(field), str) or not e[field]:
                raise SpentTracker.StateError("Invalid state " + field)
        if type(e.get("ts")) is not int or not 0 <= e["ts"] <= int(time.time()) + MAX_FUTURE_SKEW:
            raise SpentTracker.StateError("Invalid state timestamp")
        amount = _policy_decimal(e.get("amount"))
        if amount is None or amount < 0:
            raise SpentTracker.StateError("State amount must be finite and nonnegative")
        if e["asset"] == NFT_MINT_ASSET and amount != amount.to_integral_value():
            raise SpentTracker.StateError("Mint count must be integral")
        if e.get("status") not in ("pending", "confirmed"):
            raise SpentTracker.StateError("Unknown reservation status")
        h = e.get("tx_hash")
        if h is not None and (not isinstance(h, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", h)):
            raise SpentTracker.StateError("Invalid transaction hash")
        for field in ("last_ledger", "submit_ledger"):
            v = e.get(field)
            if v is not None and (type(v) is not int or not 0 < v < 2**32):
                raise SpentTracker.StateError("Invalid " + field)
        if e.get("submit_ledger") and (not e.get("last_ledger") or e["submit_ledger"] > e["last_ledger"]):
            raise SpentTracker.StateError("Inconsistent submission range")
        if e["status"] == "pending" and h and not e.get("last_ledger"):
            raise SpentTracker.StateError("Bound reservation missing expiry ledger")
        if not h and (e.get("last_ledger") or e.get("submit_ledger")):
            raise SpentTracker.StateError("Unbound reservation has ledger identity")
        return e

    def _load(self):
        try:
            raw = self.state_path.read_text()
        except FileNotFoundError:
            if self.state_path.with_suffix(".initialized").exists():
                raise self.StateError("Initialized state is missing; restore a reviewed backup. Do NOT delete state to reset limits")
            return {"entries": []}
        except OSError as ex:
            raise self.StateError("Cannot read spend state; restore a reviewed backup") from ex
        try:
            st = json.loads(raw)
            if not isinstance(st, dict):
                raise ValueError("State must be an object")
            if isinstance(st.get("entries"), list):
                entries = st["entries"]
            elif isinstance(st.get("totals"), dict):
                entries = [{"rid": "migrated", "ts": st.get("window_start"),
                            "asset": a, "amount": v, "status": "confirmed",
                            "tx_hash": None, "last_ledger": None, "submit_ledger": None}
                           for a, v in st["totals"].items()]
            else:
                raise ValueError("Unknown state structure")
            return {"entries": [self._validate_entry(e) for e in entries]}
        except (ValueError, TypeError, self.StateError) as ex:
            raise self.StateError("Corrupt spend state. Restore a reviewed backup or reconstruct ALL liabilities using audit.log and validated ledger records. Do NOT delete state or omit unresolved obligations. " + str(ex)) from ex

    def _save(self, st):
        for entry in st["entries"]:
            self._validate_entry(entry)
        atomic_private_json(self.state_path.with_suffix(".initialized"), {"initialized": True})
        atomic_private_json(self.state_path, st)

    @staticmethod
    def _prune(entries, now):
        # P1-3: unresolved liabilities are retained REGARDLESS of age.
        # Only confirmed entries age out of the rolling window; pending
        # entries stay until the ledger outcome is proven (sweep_pending).
        return [e for e in entries
                if e.get("status") == "pending"
                or now - int(e.get("ts", 0)) < ROLLING_WINDOW]

    @staticmethod
    def _totals(entries):
        t = {}
        for e in entries:
            t[e["asset"]] = t.get(e["asset"], Decimal(0)) + Decimal(e["amount"])
        return t

    @staticmethod
    def _validate_spends(spends):
        """P2-6: spends must be finite, non-negative Decimals. Negative
        amounts must never offset genuine spending."""
        problems = []
        for asset, amt in spends.items():
            if not isinstance(amt, Decimal):
                problems.append(f"{asset} spend is not a Decimal — refusing")
                continue
            if not amt.is_finite():
                problems.append(f"{asset} spend {amt} is not finite — refusing")
                continue
            if amt < 0:
                problems.append(f"{asset} spend {amt} is negative — refusing")
        return problems

    def _deny(self, spends, entries, policy):
        denials = []
        denials.extend(self._validate_spends(spends))
        if denials:
            return denials
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

    def bind_reservation(self, rid, tx_hash, last_ledger, submit_ledger=None):
        """Attach the signed transaction's identity to a reservation.

        submit_ledger (the validated ledger index at signing time) anchors
        the proven-non-inclusion check: only a node whose complete history
        covers [submit_ledger, last_ledger] can prove the tx never landed.
        """
        with self._locked():
            st = self._load()
            for e in st["entries"]:
                if e.get("rid") == rid and e.get("status") == "pending":
                    e["tx_hash"] = tx_hash
                    e["last_ledger"] = last_ledger
                    e["submit_ledger"] = submit_ledger
            self._save(st)

    def confirm(self, tx_hash):
        """Validated tesSUCCESS: entries stay and count toward the limit."""
        with self._locked():
            st = self._load()
            for e in st["entries"]:
                if e.get("tx_hash") == tx_hash and e.get("status") == "pending":
                    e["status"] = "confirmed"
                    e["ts"] = int(time.time())
            self._save(st)

    def release_tx(self, tx_hash, fee_drops=None):
        """Validated failure: drop the trade entries, but RETAIN the fee.

        A validated failed transaction still consumed its fee — releasing
        the fee reservation would under-count real spending (P1-3). The
        fee becomes a confirmed XRP entry; everything else is dropped.
        """
        with self._locked():
            st = self._load()
            kept = [e for e in st["entries"]
                    if e.get("tx_hash") != tx_hash]
            if fee_drops:
                from xrpl.utils import drops_to_xrp
                fee_xrp = Decimal(drops_to_xrp(str(fee_drops)))
                if fee_xrp > 0:
                    kept.append({
                        "rid": f"fee-{tx_hash[:16]}",
                        "ts": int(time.time()),
                        "asset": "XRP",
                        "amount": str(fee_xrp),
                        "status": "confirmed",
                        "tx_hash": tx_hash,
                        "last_ledger": None,
                        "submit_ledger": None,
                        "note": "fee consumed by validated failed tx",
                    })
            st["entries"] = kept
            self._save(st)

    @staticmethod
    def _history_covers(complete_ledgers, lo, hi) -> bool:
        """Does the node's complete history cover [lo, hi]?

        complete_ledgers looks like "1000-2000" or "1000-1100,1150-2000".
        A pruned node cannot prove non-inclusion — fail closed.
        """
        if not complete_ledgers or lo is None or hi is None:
            return False
        try:
            lo, hi = int(lo), int(hi)
            if not 0 < lo <= hi:
                return False
            for part in str(complete_ledgers).split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-", 1)
                    if int(a) <= lo and int(b) >= hi:
                        return True
                elif int(part) == lo == hi:
                    return True
        except (ValueError, TypeError):
            return False
        return False

    def sweep_pending(self, client):
        """Release only on validated outcome or explicit, history-proven absence."""
        from xrpl.models.requests import Ledger, Tx, ServerInfo
        from xrpl.utils import drops_to_xrp
        with self._locked():
            entries = self._prune(self._load()["entries"], int(time.time()))
            groups = {}
            for e in entries:
                if e["status"] == "pending" and e.get("tx_hash"):
                    groups.setdefault(e["tx_hash"], []).append(e)
            if not groups:
                self._save({"entries": entries})
                return
            try:
                lr = client.request(Ledger(ledger_index="validated"))
                if not lr.is_successful() or lr.result.get("validated") is not True:
                    return
                cur = lr.result["ledger_index"]
                sr = client.request(ServerInfo())
                complete = sr.result.get("info", {}).get("complete_ledgers", "") if sr.is_successful() else ""
            except Exception:
                return
            replacements = {}
            for h, group in groups.items():
                try:
                    r = client.request(Tx(transaction=h))
                    if not r.is_successful():
                        proven = (r.result.get("error") == "txnNotFound" and all(
                            e.get("last_ledger") and e["last_ledger"] < cur and
                            self._history_covers(complete, e.get("submit_ledger"), e["last_ledger"])
                            for e in group))
                        if proven:
                            replacements[h] = []
                        continue
                    if r.result.get("validated") is not True:
                        continue
                    result = r.result.get("meta", {}).get("TransactionResult")
                    if result == "tesSUCCESS":
                        replacements[h] = [dict(e, status="confirmed", ts=int(time.time())) for e in group]
                    elif isinstance(result, str) and result.startswith("tec"):
                        txdata = r.result.get("tx_json", r.result)
                        fee = int(txdata["Fee"])
                        if fee < 0:
                            continue
                        replacements[h] = [dict(group[0], asset="XRP", amount=str(drops_to_xrp(str(fee))),
                            status="confirmed", ts=int(time.time()), note="fee: " + result)] if fee else []
                except Exception:
                    continue  # malformed or incomplete evidence cannot free budget
            kept = [e for e in entries if not (e["status"] == "pending" and e.get("tx_hash") in replacements)]
            for group in replacements.values():
                kept.extend(group)
            self._save({"entries": kept})

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
