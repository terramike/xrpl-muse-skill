#!/usr/bin/env python3
"""v0.6.0 security tests — no network. Run: python3 tests/test_v060.py

Covers the v0.6.0 security plan items, in order:
  1. fail-closed spend state + reservation cleanup
  2. validated-ledger NFT reads
  3. terminal output sanitization
  4. full-hash approval
  5. Pinata stage vs pin-and-propose
  6. issuer-vs-seller ceremony fix
  7. strict policy schema validation
  8. docs honesty + deployment profiles (doc assertions)
  9. giveaway code gets the same treatment
  10. vault-condition verification (doc assertions)
"""
import importlib.util
import io
import contextlib
import json
import sys
from types import SimpleNamespace as ns
import tempfile
import time
import hashlib
from decimal import Decimal
from pathlib import Path

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    # Register the shared helper under the name both CLIs import, so the
    # test and the CLIs use ONE module instance.
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common")
S = load(BIN / "xrpl-sign", "xrpl_sign_v060")
T = load(BIN / "xrpl-trade", "xrpl_trade_v060")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


tmp = Path(tempfile.mkdtemp(prefix="v060-"))
# Redirect ALL shared paths to the sandbox (single module instance!).
C.XRPL_DIR = tmp
C.PROPOSALS_DIR = tmp / "proposals"
C.POLICY_PATH = tmp / "policy.json"
C.STATE_PATH = tmp / "state.json"
C.STATE_LOCK_PATH = tmp / "state.lock"
C.AUDIT_PATH = tmp / "audit.log"
C.APPROVED_PATH = tmp / "approved.json"
C.APPROVED_PATH.write_text(json.dumps({"pairs": {}}))
C.PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)

POL = {"spend_limits": {"XRP": {"per_tx": "25", "per_day": "100"}}}

ACCT = "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB"
DEST = "rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB"


def fresh_state(entries=()):
    if C.STATE_PATH.exists():
        C.STATE_PATH.unlink()
    if entries:
        C.STATE_PATH.write_text(json.dumps({"entries": list(entries)}))


def pending_entries():
    if not C.STATE_PATH.exists():
        return []
    st = json.loads(C.STATE_PATH.read_text())
    return [e for e in st.get("entries", [])
            if e.get("status") == "pending" and not e.get("tx_hash")]


# =====================================================================
# Item 1: fail-closed spend state + reservation cleanup
# =====================================================================

# --- 1a. _load fails closed on corruption ---
trk = C.SpentTracker()

fresh_state()
check("missing state file means empty state (no error)",
      trk._load() == {"entries": []})

C.STATE_PATH.write_text("{not valid json")
try:
    trk._load()
    check("corrupt JSON aborts", False)
except C.StateCorruptError as e:
    msg = str(e)
    check("corrupt JSON aborts", True)
    check("corrupt message names recovery (backup)",
          "backup" in msg)
    check("corrupt message names the audit log",
          "audit.log" in msg)
    check("corrupt message forbids deleting the file",
          "Do NOT delete" in msg)

C.STATE_PATH.write_text('{"entries": [')
try:
    trk._load()
    check("truncated JSON aborts", False)
except C.StateCorruptError:
    check("truncated JSON aborts", True)

for bad, label in [
    ('{"entries": "nope"}', "entries not a list"),
    ('[1, 2, 3]', "top-level list"),
    ('{}', "empty object"),
    ('"just a string"', "top-level string"),
]:
    C.STATE_PATH.write_text(bad)
    try:
        trk._load()
        check(f"wrong structure aborts ({label})", False)
    except C.StateCorruptError:
        check(f"wrong structure aborts ({label})", True)

now = int(time.time())
good_entry = {"rid": "r1", "ts": now, "asset": "XRP", "amount": "5",
              "status": "confirmed", "tx_hash": None, "last_ledger": None}
bad_entries = [
    ("non-dict entry", ["nope"]),
    ("bad ts type", [dict(good_entry, ts="yesterday")]),
    ("bool ts", [dict(good_entry, ts=True)]),
    ("bad asset type", [dict(good_entry, asset=123)]),
    ("bad amount", [dict(good_entry, amount="abc")]),
    ("null amount", [dict(good_entry, amount=None)]),
    ("bad status", [dict(good_entry, status="weird")]),
    ("bad rid type", [dict(good_entry, rid=42)]),
    ("bad last_ledger type", [dict(good_entry, last_ledger="12")]),
]
for label, entries in bad_entries:
    C.STATE_PATH.write_text(json.dumps({"entries": entries}))
    try:
        trk._load()
        check(f"malformed entry aborts ({label})", False)
    except C.StateCorruptError:
        check(f"malformed entry aborts ({label})", True)

fresh_state([good_entry])
check("valid state still loads",
      trk._load() == {"entries": [good_entry]})

# v0.3 single-bucket migration still works when valid...
C.STATE_PATH.write_text(json.dumps(
    {"totals": {"XRP": "7"}, "window_start": now - 100}))
loaded = trk._load()["entries"]
check("valid v0.3 totals still migrate",
      len(loaded) == 1 and loaded[0]["amount"] == "7"
      and loaded[0]["status"] == "confirmed")
# ...and fails closed when corrupt.
C.STATE_PATH.write_text(json.dumps(
    {"totals": {"XRP": "not-a-number"}, "window_start": now - 100}))
try:
    trk._load()
    check("corrupt v0.3 totals abort", False)
except C.StateCorruptError:
    check("corrupt v0.3 totals abort", True)

# --- 1b. _reserve_sign_bind releases on every pre-bind failure ---
PROP = {"action": "send", "proposal_hash": "ab" * 32, "network": "testnet"}
TX = {"Account": ACCT, "TransactionType": "Payment",
      "Destination": DEST, "Amount": "1"}
SPENDS = {"XRP": Decimal("1")}


class FakeWallet:
    classic_address = ACCT

    @staticmethod
    def from_seed(seed):
        if seed == "bogus":
            raise ValueError("bad seed")
        return FakeWallet()


class FakeSigned:
    def get_hash(self):
        return "AA" * 32


def patch_sign_env(load_seed=None, wallet_cls=None, sign_fn=None):
    """Monkeypatch the signer module's globals; returns restore()."""
    orig = (S.load_seed, S.Wallet, S.sign_tx)
    if load_seed is not None:
        S.load_seed = load_seed
    if wallet_cls is not None:
        S.Wallet = wallet_cls
    if sign_fn is not None:
        S.sign_tx = sign_fn

    def restore():
        S.load_seed, S.Wallet, S.sign_tx = orig
    return restore


def run_bind(prop=None, tx=None, policy=None, fail_seed=None,
             wallet_cls=FakeWallet, sign_fn=lambda t, w: FakeSigned()):
    fresh_state()
    tracker = C.SpentTracker()
    def _ls(env):
        raise SystemExit(f"No seed. {env} is not set")
    restore = patch_sign_env(
        load_seed=_ls if fail_seed else (lambda env: "s" * 29),
        wallet_cls=wallet_cls, sign_fn=sign_fn)
    try:
        return S._reserve_sign_bind(prop or PROP, tx or TX, policy or POL,
                                    tracker, SPENDS, "XRPL_SEED")
    finally:
        restore()


def expect_exit(name, fn, needle=None):
    try:
        fn()
    except SystemExit as e:
        ok = needle is None or needle in str(e)
        check(f"{name} (SystemExit{' ~ ' + needle if needle else ''})", ok)
        return True
    except BaseException as e:  # noqa: BLE001
        check(f"{name} (raised {type(e).__name__}, expected SystemExit)",
              False)
        return False
    check(f"{name} (expected SystemExit, completed)", False)
    return False


# missing seed: the headline regression — reservation must not leak
expect_exit("missing seed aborts", lambda: run_bind(fail_seed=True),
            "No seed")
check("missing seed leaves zero pending reservations",
      pending_entries() == [])

# invalid seed
expect_exit("invalid seed aborts",
            lambda: run_bind(wallet_cls=type(
                "W", (), {"from_seed": staticmethod(
                    lambda s: (_ for _ in ()).throw(ValueError("bad"))),
                    "classic_address": ACCT})),
            "Seed invalid")
check("invalid seed leaves zero pending reservations",
      pending_entries() == [])


class WrongWallet:
    classic_address = DEST

    @staticmethod
    def from_seed(seed):
        return WrongWallet()


expect_exit("wallet mismatch aborts", lambda: run_bind(wallet_cls=WrongWallet),
            "wallet mismatch")
check("wallet mismatch leaves zero pending reservations",
      pending_entries() == [])

# signing throws (raw exception, e.g. serialization bug)
try:
    def _boom(t, w):
        raise RuntimeError("serialization blew up")
    run_bind(sign_fn=_boom)
    check("signing failure releases reservation", False)
except RuntimeError:
    check("signing failure propagates", True)
    check("signing failure leaves zero pending reservations",
          pending_entries() == [])

# KeyboardInterrupt (operator ^C mid-sign)
try:
    def _intr(t, w):
        raise KeyboardInterrupt()
    run_bind(sign_fn=_intr)
    check("KeyboardInterrupt releases reservation", False)
except KeyboardInterrupt:
    check("KeyboardInterrupt propagates", True)
    check("KeyboardInterrupt leaves zero pending reservations",
          pending_entries() == [])

# success path: reservation binds, is NOT released
fresh_state()
tracker = C.SpentTracker()
restore = patch_sign_env(load_seed=lambda env: "s" * 29,
                         wallet_cls=FakeWallet,
                         sign_fn=lambda t, w: FakeSigned())
try:
    signed, thash, last_ledger = S._reserve_sign_bind(
        PROP, TX, POL, tracker, SPENDS, "XRPL_SEED")
    check("success path returns the tx hash", thash == "AA" * 32)
    st = json.loads(C.STATE_PATH.read_text())["entries"]
    check("success path binds (not releases) the reservation",
          len(st) == 1 and st[0]["tx_hash"] == "AA" * 32
          and st[0]["status"] == "pending")
finally:
    restore()

# mint-quota denial releases the spend reservation too
MINT_TX = dict(TX, TransactionType="NFTokenMint")
MINT_POL = dict(POL)
MINT_POL["nft"] = {"max_mints_per_day": 0}
expect_exit("mint-quota denial aborts",
            lambda: run_bind(tx=MINT_TX, policy=MINT_POL),
            "Mint-quota reservation failed")
check("mint-quota denial leaves zero pending reservations",
      pending_entries() == [])

# corrupt state at reserve time -> clean abort naming recovery
C.STATE_PATH.write_text("{corrupt")
try:
    S._reserve_sign_bind(PROP, TX, POL, C.SpentTracker(), SPENDS, "XRPL_SEED")
    check("corrupt state at reserve aborts cleanly", False)
except SystemExit as e:
    check("corrupt state at reserve aborts cleanly", "CORRUPT" in str(e))
except C.StateCorruptError:
    check("corrupt state at reserve aborts cleanly (raw, not sys.exit)",
          False)

# daily-limit denial (no reservation made): clean message, nothing pending
BIG = {"XRP": Decimal("1000")}
fresh_state()
restore = patch_sign_env(load_seed=lambda env: "s" * 29)
try:
    S._reserve_sign_bind(PROP, TX, POL, C.SpentTracker(), BIG, "XRPL_SEED")
    check("over-limit reserve denied", False)
except SystemExit as e:
    check("over-limit reserve denied", "Daily-limit reservation failed" in str(e))
    check("denied reserve leaves zero pending reservations",
          pending_entries() == [])
finally:
    restore()

# =====================================================================
# Item 2: validated-ledger NFT reads
# =====================================================================
from xrpl.models.requests import AccountNFTs as _AccountNFTs
from xrpl.models.requests import Ledger as _Ledger
from xrpl.models.requests import LedgerEntry as _LedgerEntry

TOKEN2 = "CD" * 32
OFFER2 = "EF" * 32
ARTIST = "r9cZA1mLK5R5Am25ArfXFmqgNwjZgnfk59"  # minter, distinct from ACCT


class _V2Resp:
    def __init__(self, ok, result):
        self._ok = ok
        self.result = result

    def is_successful(self):
        return self._ok


class _V2Client:
    """Mock ledger for item 2: records every read's ledger_index and can
    serve unvalidated data on demand."""

    def __init__(self, validated_index=91000, data_validated=True,
                 offer=None, nfts=(), ledger_ok=True):
        self.validated_index = validated_index
        self.data_validated = data_validated
        self.offer = offer
        self.nfts = list(nfts)
        self.ledger_ok = ledger_ok
        self.reads = []  # (kind, ledger_index) for every data read

    def request(self, req):
        if isinstance(req, _Ledger):
            if not self.ledger_ok:
                return _V2Resp(False, {"error": "ledger_missing"})
            return _V2Resp(True, {"ledger_index": self.validated_index,
                                  "validated": True})
        if isinstance(req, _LedgerEntry):
            self.reads.append(("offer", req.ledger_index))
            if self.offer is None:
                return _V2Resp(False, {"error": "entryNotFound"})
            return _V2Resp(True, {"node": self.offer,
                                  "ledger_index": req.ledger_index,
                                  "validated": self.data_validated})
        if isinstance(req, _AccountNFTs):
            self.reads.append(("nfts", req.ledger_index))
            return _V2Resp(True, {"account_nfts": self.nfts,
                                  "ledger_index": req.ledger_index,
                                  "validated": self.data_validated})
        raise AssertionError(f"unexpected request {type(req).__name__}")


def _sell_entry2():
    return {"LedgerEntryType": "NFTokenOffer", "Flags": 1,
            "Amount": "2000000", "Owner": ACCT, "NFTokenID": TOKEN2}


def _seller_nfts2(issuer=ARTIST):
    return [{"NFTokenID": TOKEN2,
             "URI": "ipfs://bafytest".encode().hex().upper(),
             "NFTokenTaxon": 7,
             "Issuer": issuer}]


vc = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2())
entry, problem = C.fetch_nft_offer_entry(vc, OFFER2)
check("offer fetch defaults to ledger_index='validated'",
      problem is None and vc.reads == [("offer", "validated")])

vc2 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2())
entry, problem = C.fetch_nft_offer_entry(vc2, OFFER2, 91000)
check("offer fetch accepts a pinned ledger index",
      problem is None and vc2.reads == [("offer", 91000)])

vc3 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2(),
               data_validated=False)
entry, problem = C.fetch_nft_offer_entry(vc3, OFFER2)
check("unvalidated offer data refused",
      entry is None and problem is not None and "unvalidated" in problem)

vc4 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2())
uri, taxon, issuer, problem = C.fetch_nft_meta(vc4, ACCT, TOKEN2)
check("inventory fetch defaults to ledger_index='validated'",
      problem is None and vc4.reads == [("nfts", "validated")]
      and taxon == 7)
check("inventory fetch returns the on-ledger issuer (minter)",
      issuer == ARTIST)

vc5 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2(),
               data_validated=False)
uri, taxon, issuer, problem = C.fetch_nft_meta(vc5, ACCT, TOKEN2)
check("unvalidated inventory data refused",
      uri is None and problem is not None and "unvalidated" in problem)

# the report pins the offer AND the inventory read to ONE validated index
vc6 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2())
lines, denials, amt = C.nft_sell_offer_report(vc6, OFFER2)
check("report verifies clean on validated data",
      not denials and amt == Decimal("2"))
kinds = {k for k, _ in vc6.reads}
idxs = {i for _, i in vc6.reads}
check("report pins offer+inventory to one validated ledger index",
      kinds == {"offer", "nfts"} and idxs == {vc6.validated_index})

# --- Item 6: issuer (minter) is distinct from seller (current owner) ---
vc7 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2())
lines7, denials7, _ = C.nft_sell_offer_report(vc7, OFFER2)
check("report labels seller as current owner, issuer as minter",
      not denials7
      and f"seller:   {ACCT} (current owner)" in lines7
      and f"issuer:   {ARTIST} (minter)" in lines7)

# even when the seller IS the minter, both lines stay explicit
vc8 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2(issuer=ACCT))
lines8, denials8, _ = C.nft_sell_offer_report(vc8, OFFER2)
check("issuer==seller still shows both lines explicitly",
      not denials8
      and f"seller:   {ACCT} (current owner)" in lines8
      and f"issuer:   {ACCT} (minter)" in lines8)

# a missing issuer degrades to unknown rather than crashing
nft_no_issuer = dict(_seller_nfts2()[0])
nft_no_issuer.pop("Issuer")
vc9 = _V2Client(offer=_sell_entry2(), nfts=[nft_no_issuer])
lines9, denials9, _ = C.nft_sell_offer_report(vc9, OFFER2)
check("missing issuer renders as unknown, not an exception",
      not denials9 and "issuer:   ? (minter)" in lines9)

# ceremony instructions no longer equate seller with minter
_src = Path(BIN / "xrpl-trade").read_text()
check("buy banner names the issuer, not the seller, as the artist to verify",
      "Verify the ISSUER is the artist you expect" in _src
      and "SELLER is the minter" not in _src)
_sign_src = Path(BIN / "xrpl-sign").read_text()
check("signing ceremony names the issuer as the artist to verify",
      "VERIFY the issuer below is the artist you expect" in _sign_src
      and "the seller below is the minter" not in _sign_src)

vc7 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2(),
               data_validated=False)
lines, denials, amt = C.nft_sell_offer_report(vc7, OFFER2)
check("report refuses unvalidated node data",
      amt is None and any("unvalidated" in d for d in denials))

vc8 = _V2Client(offer=_sell_entry2(), nfts=_seller_nfts2(), ledger_ok=False)
lines, denials, amt = C.nft_sell_offer_report(vc8, OFFER2)
check("report refuses when the validated ledger is unreadable",
      amt is None and denials)

# =====================================================================
# Item 3: terminal output sanitization
# =====================================================================
EVIL_URI_TXT = ("ipfs://bafy\x1b[31mRED\x1b[0m\n"
                "fake price: 0.000001 XRP\x1b]52;c;YmFk\x07"
                "\u202a\u202e100\u202c")
SAFE = C.safe_terminal_text

check("ANSI escapes neutralized",
      "\x1b" not in SAFE("\x1b[31mred\x1b[0m")
      and "\\x1b[31m" in SAFE("\x1b[31mred\x1b[0m"))
check("OSC-52 clipboard sequence neutralized",
      "\x1b" not in SAFE("\x1b]52;c;YmFk\x07")
      and "\\x1b]52;c;YmFk\\x07" in SAFE("\x1b]52;c;YmFk\x07"))
check("embedded newlines escaped",
      SAFE("line1\nline2\rline3") == "line1\\nline2\\rline3")
check("tab escaped", SAFE("a\tb") == "a\\tb")
check("bidi overrides escaped",
      "\u202a\u202e" not in SAFE("\u202a\u202e100\u202c")
      and "\\u202e" in SAFE("\u202a\u202e100\u202c"))
check("C1 controls escaped", SAFE("\x85") == "\\u0085")
check("DEL escaped", SAFE("\x7f") == "\\x7f")
check("legit Unicode survives",
      SAFE("🎨 Café — 日本語 ＄100") == "🎨 Café — 日本語 ＄100")
check("None and non-str never raise",
      SAFE(None) == "" and SAFE(123) == "123")
check("limit truncates after sanitizing",
      SAFE("y" * 400, 300) == "y" * 299 + "…")

evil_hex = EVIL_URI_TXT.encode("utf-8").hex()
decoded = C.decode_nft_uri(evil_hex, 500)
check("decode_nft_uri sanitizes",
      "\x1b" not in decoded and "\n" not in decoded
      and "\\x1b[31m" in decoded and "\\n" in decoded)
check("decode_nft_uri still enforces its limit",
      C.decode_nft_uri("ab" * 200, 90).endswith("…"))

mint_tx = {"TransactionType": "NFTokenMint", "Account": ACCT,
           "NFTokenTaxon": 7, "URI": evil_hex, "TransferFee": "1000",
           "Flags": 9}
desc = "\n".join(C.describe_tx(mint_tx, "nft-mint"))
check("describe_tx sanitizes the mint URI",
      "\x1b" not in desc and "\\x1b[31m" in desc)

# report path with an evil on-ledger URI
vc9 = _V2Client(offer=_sell_entry2(),
               nfts=[{"NFTokenID": TOKEN2, "URI": evil_hex.upper(),
                      "NFTokenTaxon": 7}])
lines, denials, amt = C.nft_sell_offer_report(vc9, OFFER2)
rep = "\n".join(lines)
check("sell-offer report sanitizes the URI",
      not denials and "\x1b" not in rep and "\\x1b[31m" in rep)

XP = load(BIN / "xrpl_xrpresso.py", "xrpl_xrpresso_v060")
check("xrpresso _text sanitizes (was truncate-only)",
      "\x1b" not in XP._text("\x1b[2Jtitle")
      and "\\x1b[2J" in XP._text("\x1b[2Jtitle"))
check("xrpresso _text keeps the 300-char cap",
      len(XP._text("y" * 400)) == 300)

# =====================================================================
# Item 4: full-hash approval
# =====================================================================
FULL4 = "ab" * 32
PROP4 = {"proposal_hash": FULL4}


def _expect_exit(fn, *a, **k):
    try:
        fn(*a, **k)
    except SystemExit as e:
        return str(e)
    return None


msg = _expect_exit(C.require_full_hash_for_approve, FULL4[:16], PROP4)
check("prefix + approve refused",
      msg is not None and "FULL 64-character" in msg and FULL4 in msg)
check("exact full hash + approve allowed",
      _expect_exit(C.require_full_hash_for_approve, FULL4, PROP4) is None)
msg = _expect_exit(C.require_full_hash_for_approve, "cd" * 32, PROP4)
check("wrong full hash + approve refused", msg is not None)
msg = _expect_exit(C.require_full_hash_for_approve, None, PROP4)
check("missing --hash + approve refused", msg is not None)
msg = _expect_exit(C.require_full_hash_for_approve, FULL4[:16], PROP4)
check("refusal message is re-runnable",
      msg is not None and f"--hash {FULL4} --approve" in msg)

# prefixes remain read-only: load_proposal still resolves them
with tempfile.TemporaryDirectory() as td:
    old_dir = C.PROPOSALS_DIR
    C.PROPOSALS_DIR = Path(td)
    try:
        (Path(td) / f"{FULL4}.json").write_text(
            json.dumps({"proposal_hash": FULL4}))
        prop, path = C.load_proposal(FULL4[:16])
        check("prefix still loads for read-only review",
              prop["proposal_hash"] == FULL4)
        msg = _expect_exit(C.require_full_hash_for_approve,
                           FULL4[:16], prop)
        check("that same prefix is refused for --approve",
              msg is not None and "FULL 64-character" in msg)
    finally:
        C.PROPOSALS_DIR = old_dir

cmd = C.giveaway_sign_command(FULL4)
check("giveaway sign command carries the full hash",
      f"--hash {FULL4} --approve" in cmd
      and f"--hash {FULL4[:16]} --approve" not in cmd)

# =====================================================================
# Item 5: Pinata stage vs pin-and-propose
# =====================================================================
import os as _os
import socket as _socket
import urllib.request as _urlreq

PIN = load(BIN / "xrpl_pin.py", "xrpl_pin")
T.xrpl_pin = PIN  # share one module instance, like the CLIs do
C.STAGE_DIR = tmp / "stage"

media = tmp / "media"
media.mkdir()


def _make_png(path, filler=b"\x00" * 64):
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + filler)
    return path


png1 = _make_png(media / "art1.png")

# --- 5a. read_validated_source unit checks ---
data, info = PIN.read_validated_source(str(png1), media_dir=str(media))
check("valid PNG passes validation",
      info["mime"] == "image/png" and info["bytes"] == 72
      and info["sha256"] == hashlib.sha256(
          b"\x89PNG\r\n\x1a\n" + b"\x00" * 64).hexdigest())

txt = media / "note.txt"
txt.write_text("hello")
check("wrong MIME refused",
      _expect_exit(PIN.read_validated_source, str(txt),
                   media_dir=str(media)) is not None)

old_max = PIN.NFT_MAX_BYTES
PIN.NFT_MAX_BYTES = 32
try:
    msg = _expect_exit(PIN.read_validated_source, str(png1),
                       media_dir=str(media))
finally:
    PIN.NFT_MAX_BYTES = old_max
check("oversized file refused",
      msg is not None and "exceeds" in msg)

_os.symlink("/etc/hostname", media / "escape.png")
check("symlink escape refused",
      _expect_exit(PIN.read_validated_source, str(media / "escape.png"),
                   media_dir=str(media)) is not None)

_os.symlink("art1.png", media / "link.png")
data2, info2 = PIN.read_validated_source(str(media / "link.png"),
                                         media_dir=str(media))
check("symlink inside the media dir resolves and is allowed",
      info2["sha256"] == info["sha256"])

empty = media / "empty.png"
empty.write_bytes(b"")
check("empty file refused",
      _expect_exit(PIN.read_validated_source, str(empty),
                   media_dir=str(media)) is not None)

check("missing media dir refused",
      _expect_exit(PIN.read_validated_source, str(png1),
                   media_dir=str(tmp / "nomedia")) is not None)

jpg = media / "a.jpg"
jpg.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 32)
check("JPEG magic recognized",
      PIN.read_validated_source(str(jpg), media_dir=str(media))[1]["mime"]
      == "image/jpeg")

# --- 5b. nft-stage: zero network calls ---
rec = T.stage_artwork(str(png1), "Net Test", "d", 1000, 7,
                      media_dir=str(media))
check("stage record binds file hash + metadata",
      rec["sha256"] == info["sha256"] and rec["mime"] == "image/png"
      and rec["metadata"] == {"name": "Net Test", "description": "d",
                              "image": None}
      and rec["royalty_bps"] == 1000 and rec["taxon"] == 7
      and len(rec["stage_id"]) == 16)
check("stage record persisted",
      (C.STAGE_DIR / f"{rec['stage_id']}.json").exists())


def _no_network(*a, **k):
    raise AssertionError("network used during nft-stage")


_old_cc, _old_uo = _socket.create_connection, _urlreq.urlopen
_socket.create_connection = _no_network
_urlreq.urlopen = _no_network
try:
    rec_net = T.stage_artwork(str(png1), "Net Test 2", "", 1000, 0,
                              media_dir=str(media))
finally:
    _socket.create_connection = _old_cc
    _urlreq.urlopen = _old_uo
check("nft-stage completes with networking disabled", bool(rec_net))

check("royalty over 5000bps refused at stage",
      _expect_exit(T.stage_artwork, str(png1), "X", "", 5001, 0,
                   media_dir=str(media)) is not None)
check("oversized taxon refused at stage",
      _expect_exit(T.stage_artwork, str(png1), "X", "", 1000, 2 ** 32,
                   media_dir=str(media)) is not None)
check("empty name refused at stage",
      _expect_exit(T.stage_artwork, str(png1), "  ", "", 1000, 0,
                   media_dir=str(media)) is not None)

# --- 5c. nft-pin-and-propose with a fake pinner (no network) ---
_old_autofill = T.autofill


def _fake_autofill(tx, client):
    from xrpl.models.transactions import NFTokenMint as _M
    d = tx.to_dict()
    d.pop("transaction_type", None)
    return _M(**{**d, "fee": "12", "sequence": 1,
                 "last_ledger_sequence": 999})


T.autofill = _fake_autofill


class _FakePinner:
    def __init__(self, name="Net Test", description="d"):
        self.name = name
        self.description = description
        self.pinned = []

    def read_validated_source(self, path, media_dir=None):
        return PIN.read_validated_source(path, media_dir=media_dir)

    def pin_file(self, path, media_dir=None):
        self.pinned.append(("file", path))
        return "bafyfakeimagecid"

    def pin_json(self, obj, name="metadata.json"):
        assert obj == {"name": self.name, "description": self.description,
                       "image": "ipfs://bafyfakeimagecid"}, obj
        self.pinned.append(("json", name))
        return "bafyfakemetacid"


cfg5 = {"network": "testnet", "address": ACCT}
h5 = T.pin_and_propose_stage(rec["stage_id"], cfg5, None,
                             pinner=_FakePinner())
prop5 = json.loads((C.PROPOSALS_DIR / f"{h5}.json").read_text())
want_uri = "ipfs://bafyfakemetacid".encode("utf-8").hex().upper()
check("pin-and-propose proposes the mint",
      prop5["action"] == "nft-mint" and prop5["tx"]["URI"] == want_uri
      and prop5["tx"]["TransferFee"] == 10000
      and prop5["proposal_hash"] == h5)

# the Pinata secret must not leak into proposals or the audit log
_os.environ["PINATA_JWT"] = "canary-jwt-xyz"


class _LeakPinner(_FakePinner):
    def pin_file(self, path, media_dir=None):
        assert PIN._jwt() == "canary-jwt-xyz"  # read at pin time, prod path
        return super().pin_file(path)


png3 = _make_png(media / "art3.png", b"\x02" * 64)
rec3 = T.stage_artwork(str(png3), "Leak Test", "", 1000, 0,
                       media_dir=str(media))
h_leak = T.pin_and_propose_stage(rec3["stage_id"], cfg5, None,
                                 pinner=_LeakPinner("Leak Test", ""))
leak_prop = (C.PROPOSALS_DIR / f"{h_leak}.json").read_text()
audit_txt = C.AUDIT_PATH.read_text() if C.AUDIT_PATH.exists() else ""
check("PINATA_JWT never lands in proposals or audit log",
      "canary-jwt-xyz" not in leak_prop
      and "canary-jwt-xyz" not in audit_txt)
del _os.environ["PINATA_JWT"]

# --- 5d. tamper / corruption handling ---
png4 = _make_png(media / "art4.png", b"\x03" * 64)
rec4 = T.stage_artwork(str(png4), "Tamper", "", 1000, 0,
                       media_dir=str(media))
png4.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x04" * 64)  # swap after staging
msg = _expect_exit(T.pin_and_propose_stage, rec4["stage_id"], cfg5, None,
                   _FakePinner("Tamper", ""))
check("file changed since staging is refused at pin time",
      msg is not None and "changed since staging" in msg)

check("unknown stage id refused",
      _expect_exit(T.load_stage_record, "deadbeef") is not None)
(C.STAGE_DIR / "bad.json").write_text("{not json")
check("corrupt stage record refused",
      _expect_exit(T.load_stage_record, "bad") is not None)
(C.STAGE_DIR / "aabbccdd0001.json").write_text(json.dumps(
    {"format": "nft-stage/1"}))
(C.STAGE_DIR / "aabbccdd0002.json").write_text(json.dumps(
    {"format": "nft-stage/1"}))
check("ambiguous stage prefix refused",
      _expect_exit(T.load_stage_record, "aabbccdd") is not None)

T.autofill = _old_autofill

# =====================================================================
# Item 7: strict policy schema
# =====================================================================

def _good_policy():
    return json.loads(json.dumps(C.DEFAULT_POLICY))


def _schema_problem(mutator):
    pol = _good_policy()
    mutator(pol)
    try:
        C.validate_policy(pol)
    except C.PolicyError as e:
        return str(e)
    return None


def _expect_schema_error(name, mutator, needle):
    msg = _schema_problem(mutator)
    check(name, msg is not None and needle in msg)


check("golden-path default policy validates",
      C.validate_policy(_good_policy()) == _good_policy())

# a realistic operator policy also validates
def _operator(pol):
    pol["spend_limits"] = {"XRP": {"per_tx": "25", "per_day": "100"},
                           "USD": {"per_tx": 50, "per_day": "500"}}
    pol["destination_allowlist"] = [
        {"address": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
         "destination_tag": 777},
        {"address": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
         "destination_tag": None}]
    pol["network_lock"] = "mainnet"
check("realistic operator policy validates",
      _schema_problem(_operator) is None)

# the giveaway variant (extra known keys) validates too
check("giveaway policy shape validates",
      C.validate_policy(C.default_giveaway_policy("10", "testnet"))
      is not None)

_expect_schema_error(
    "unknown top-level key refused",
    lambda p: p.update({"evil_key": 1}), "unknown policy key")
_expect_schema_error(
    "lone parked value-policy field refused, not silently ignored",
    lambda p: p["nft"].update({"allowed_nft_issuers": ["r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB"]}),
    "nft: unknown key")
_expect_schema_error(
    "missing required key refused",
    lambda p: p.pop("spend_limits"), "missing required policy key")
_expect_schema_error(
    "wrong type: max_fee_drops as string",
    lambda p: p.update({"max_fee_drops": "1000"}), "max_fee_drops")
_expect_schema_error(
    "wrong type: max_fee_drops as bool",
    lambda p: p.update({"max_fee_drops": True}), "max_fee_drops")
_expect_schema_error(
    "wrong type: allow_buy_offers as int",
    lambda p: p["nft"].update({"allow_buy_offers": 1}),
    "allow_buy_offers")
_expect_schema_error(
    "wrong type: allowed_tx_types as string",
    lambda p: p.update({"allowed_tx_types": "Payment"}),
    "allowed_tx_types must be a list")
_expect_schema_error(
    "wrong type: spend limit as float",
    lambda p: p["spend_limits"]["XRP"].update({"per_tx": 1.5}),
    "non-negative decimal")
_expect_schema_error(
    "negative spend cap refused",
    lambda p: p["spend_limits"]["XRP"].update({"per_tx": "-1"}),
    "non-negative decimal")
_expect_schema_error(
    "bad classic address refused",
    lambda p: p.update({"destination_allowlist":
                        [{"address": "notanaddress"}]}),
    "not a valid classic address")
_expect_schema_error(
    "destination_tag out of range refused",
    lambda p: p.update({"destination_allowlist":
                        [{"address": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
                          "destination_tag": 2 ** 32}]}),
    "destination_tag")
_expect_schema_error(
    "unknown key inside allowlist entry refused",
    lambda p: p.update({"destination_allowlist":
                        [{"address": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
                          "memo": "x"}]}),
    "unknown key")
_expect_schema_error(
    "unsupported transaction type refused",
    lambda p: p.update({"allowed_tx_types": ["Payment", "EscrowCreate"]}),
    "unsupported transaction type")
_expect_schema_error(
    "unsupported network refused",
    lambda p: p.update({"network_lock": "sidechain"}), "network_lock")
_expect_schema_error(
    "zero proposal TTL refused",
    lambda p: p.update({"proposal_ttl_seconds": 0}),
    "proposal_ttl_seconds")
_expect_schema_error(
    "negative fee cap refused",
    lambda p: p.update({"max_fee_drops": -5}), "max_fee_drops")
_expect_schema_error(
    "oversized fee cap refused",
    lambda p: p.update({"max_fee_drops": 10 ** 12}), "max_fee_drops")
_expect_schema_error(
    "bad mint flag bit refused",
    lambda p: p["nft"].update({"allowed_mint_flags": [1, 16]}),
    "allowed_mint_flags")

# ...while the explicit buy-side opt-in pair validates
def _buy_opt_in(pol):
    pol["nft"]["allow_buy_offers"] = True
    pol["allowed_tx_types"] = (pol["allowed_tx_types"]
                               + ["NFTokenAcceptOffer"])
check("explicit buy-side opt-in validates",
      _schema_problem(_buy_opt_in) is None)
# and the flag alone (bids allowed, accepts not) is coherent too
check("allow_buy_offers alone is coherent (bids are NFTokenCreateOffer)",
      _schema_problem(
          lambda p: p["nft"].update({"allow_buy_offers": True})) is None)

# load_policy surfaces the schema error fail-closed
C.POLICY_PATH.write_text(json.dumps(
    {**_good_policy(), "max_fee_drops": -1}))
msg = _expect_exit(C.load_policy)
check("load_policy refuses a schema-violating file",
      msg is not None and "policy schema violation" in msg)
C.POLICY_PATH.write_text(json.dumps(_good_policy()))
check("load_policy loads the golden-path policy",
      C.load_policy()["policy_version"] == C.POLICY_VERSION)

# the trade CLI's provisional check stays best-effort: a schema-violating
# policy degrades to "signer enforces" instead of doing limit math on
# garbage (the signer hard-refuses via load_policy).
C.POLICY_PATH.write_text(json.dumps(
    {**_good_policy(), "max_fee_drops": -1}))
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    T.provisional_spend_check({"XRP": Decimal("1")})
check("provisional check defers to the signer on schema violation",
      "fails schema validation" in buf.getvalue())
C.POLICY_PATH.write_text(json.dumps(_good_policy()))

# =====================================================================
# Item 8: docs honesty + installer
# =====================================================================
REPO = Path(__file__).resolve().parent.parent


def _doc(name):
    return (REPO / name).read_text()


readme = _doc("README.md")
skillmd = _doc("SKILL.md")
secmd = _doc("SECURITY.md")
installsh = _doc("install.sh")
pinatamd = _doc("references/nft-pinata.md")

check("README drops 'safe for humans too'",
      "safe for humans too" not in readme)
check("README states the testnet-safe / vault-mainnet posture",
      "Testnet-safe by default" in readme and "Muse vault" in readme)
check("README documents the three deployment profiles",
      all(p in readme for p in ("Muse vault signer", "Xaman-human",
                                "Autonomous-experimental")))
check("README states NFT checks don't cover value or art ownership",
      "does **not** protect market value" in readme)
check("SKILL.md has no export-PINATA_JWT pattern",
      "export PINATA_JWT" not in skillmd)
check("SKILL.md documents the two-step mint flow",
      "nft-stage" in skillmd and "nft-pin-and-propose" in skillmd)
check("SKILL.md states the same-user boundary",
      "same-user local agent does **not** satisfy" in skillmd)
check("SECURITY.md states 0600 doesn't stop same-UID",
      "same-UID process can read the signer's environment" in secmd)
check("SECURITY.md documents the v0.6.0 safety additions",
      "Full-hash approval" in secmd and "Strict policy schema" in secmd)
check("pinata doc shows injection, not export",
      "export PINATA_JWT" not in pinatamd
      and "never exported into a shell" in pinatamd)
check("pinata doc describes pinning inside the approved action",
      "the approved action, never before it" in pinatamd)
check("installer uses the hash-pinned requirements",
      "requirements-locked.txt" in installsh
      and 'pip install -r "$DEST/requirements.txt"' not in installsh)
check("installer prints the testnet-only notice",
      "TESTNET-ONLY" in installsh and "same-user" in installsh)

# =====================================================================
# Item 9: giveaway paths get the same treatment
# =====================================================================
C.GIVEAWAY_STATE_PATH = tmp / "giveaway_state.json"
C.GIVEAWAY_STATE_LOCK_PATH = tmp / "giveaway_state.lock"
C.GIVEAWAY_PATH = tmp / "giveaway.json"
C.GIVEAWAY_POLICY_PATH = tmp / "giveaway_policy.json"
C.GIVEAWAY_LAST_DRAW_PATH = tmp / "giveaway_last_draw.json"

# --- item 1: the separate giveaway state file fails closed ---
C.GIVEAWAY_STATE_PATH.write_text("{corrupt")
try:
    C.SpentTracker(state_path=C.GIVEAWAY_STATE_PATH,
                   lock_path=C.GIVEAWAY_STATE_LOCK_PATH).check(
                       {"XRP": Decimal("1")}, _good_policy())
    _gw_corrupt_ok = False
except C.StateCorruptError as e:
    _gw_corrupt_ok = "CORRUPT" in str(e)
check("corrupt giveaway_state.json fails closed (not empty)", _gw_corrupt_ok)
C.GIVEAWAY_STATE_PATH.unlink(missing_ok=True)


# --- item 2: giveaway NFT ownership refuses unvalidated data ---
class _NFTResp:
    def __init__(self, result):
        self.result = result

    def is_successful(self):
        return True


class _NFTClientRaw:
    """Returns the requested ledger_index=validated but no confirmation."""

    def __init__(self, validated):
        self.validated = validated

    def request(self, req):
        res = {"account_nfts": [{"NFTokenID": "AB" * 32}]}
        if self.validated:
            res["validated"] = True
        return _NFTResp(res)


try:
    T.donation_wallet_owns_nft(_NFTClientRaw(False), "rGW", "AB" * 32)
    _gw_unvalidated_ok = False
except SystemExit as e:
    _gw_unvalidated_ok = "unvalidated" in str(e)
check("giveaway NFT ownership refuses unvalidated ledger data",
      _gw_unvalidated_ok)
check("giveaway NFT ownership passes validated data",
      T.donation_wallet_owns_nft(_NFTClientRaw(True), "rGW",
                                 "AB" * 32) is True)


# --- item 3: announce sanitizes the human-supplied prize text ---
from xrpl.wallet import Wallet as _Wallet  # noqa: E402

_winner = _Wallet.create().classic_address
_donor = _Wallet.create().classic_address
C.GIVEAWAY_LAST_DRAW_PATH.write_text(json.dumps({
    "winner": _winner, "ledger_index": 123, "ledger_hash": "00" * 32,
    "method": "sha256(ledger_hash:tx_hashes)", "digest": "ff" * 32,
    "entrant_count": 3}))
_gw = {"donation_wallet": _donor, "network": "testnet", "opt_in_tag": 777,
       "max_gift_xrp": "10"}
_buf = io.StringIO()
with contextlib.redirect_stdout(_buf):
    T.cmd_giveaway_announce(ns(winner=None, prize="\x1b[31m5 XRP\x1b[0m"
                                                 "\u202eEVIL"), _gw)
_out = _buf.getvalue()
check("announce strips ANSI/bidi from the prize text",
      "\x1b" not in _out and "\u202e" not in _out and "5 XRP" in _out)


# --- item 2 (cont.): giveaway status inventory refuses unvalidated data ---
class _StatusResp:
    def __init__(self, result):
        self.result = result

    def is_successful(self):
        return True


class _StatusClient:
    """AccountInfo/Lines fine; the NFT page omits the validated flag."""

    def request(self, req):
        name = type(req).__name__
        if name == "AccountInfo":
            return _StatusResp({"account_data": {"Balance": "1000000"}})
        if name == "AccountLines":
            return _StatusResp({"lines": []})
        return _StatusResp({"account_nfts": []})


C.GIVEAWAY_PATH.write_text(json.dumps({"donation_wallet": _donor}))
try:
    T.cmd_giveaway(ns(gw_cmd="status", donation_wallet=_donor),
                   {"address": _winner, "network": "testnet"},
                   _StatusClient())
    _status_unval_ok = False
except SystemExit as e:
    _status_unval_ok = "unvalidated" in str(e)
check("giveaway status refuses unvalidated NFT inventory", _status_unval_ok)
C.GIVEAWAY_PATH.unlink(missing_ok=True)
# the real giveaway policy shape (narrow tx types, per_tx cap) passes
C.write_giveaway_policy("10", "testnet")
_gw_real = C.load_policy(str(C.GIVEAWAY_POLICY_PATH))
check("real giveaway policy passes the strict schema",
      _gw_real["giveaway"] is True
      and _gw_real["allowed_tx_types"] == ["Payment", "NFTokenCreateOffer"])
C.GIVEAWAY_POLICY_PATH.unlink(missing_ok=True)
# ... and a schema violation in it is still refused
_gwpol = C.default_giveaway_policy("10", "testnet")
_gwpol["spend_limits"]["XRP"]["per_tx"] = "-5"
C.GIVEAWAY_POLICY_PATH.write_text(json.dumps(_gwpol))
try:
    C.load_policy(str(C.GIVEAWAY_POLICY_PATH))
    _gw_schema_ok = False
except SystemExit as e:
    # load_policy fails closed via SystemExit (never returns bad policy)
    _gw_schema_ok = "per_tx" in str(e)
check("giveaway policy schema violations refused", _gw_schema_ok)
C.GIVEAWAY_POLICY_PATH.unlink(missing_ok=True)


# --- item 5 review: seed storage is env-first, never echoed ---
_os.environ.pop("XRPL_SEED", None)
_os.environ.pop(C.GIVEAWAY_SEED_ENV, None)
try:
    S.load_seed()
    _seed_hint_ok = False
except SystemExit as e:
    _seed_hint_ok = ("the vault did not inject XRPL_SEED" in str(e)
                     and "export XRPL_SEED" not in str(e))
check("missing-seed hint names vault injection, not export", _seed_hint_ok)

# =====================================================================
# Item 10: vault-condition verification (honest, empirical)
# =====================================================================

# --- what check_protected_files actually enforces ---
# (normalize the sandbox first: earlier tests create files with the
# default umask, and the check correctly refuses those)
C.POLICY_PATH.write_text(json.dumps(_good_policy()))
for _p in (C.POLICY_PATH, C.APPROVED_PATH, C.FAVORITES_PATH,
           C.STATE_PATH, C.STATE_LOCK_PATH, C.AUDIT_PATH):
    if _p.exists():
        _os.chmod(_p, 0o600)
try:
    C.check_protected_files()
    _prot_ok = True
except SystemExit:
    _prot_ok = False
check("protected-files check passes on owner-only 0600 state", _prot_ok)

_os.chmod(C.POLICY_PATH, 0o640)
try:
    C.check_protected_files()
    _prot_refused = False
except SystemExit as e:
    _prot_refused = "group/world-accessible" in str(e)
check("protected-files check refuses group-readable policy", _prot_refused)

# absent files are skipped (only an absent state file means empty state)
C.POLICY_PATH.unlink()
try:
    C.check_protected_files()
    _prot_missing_ok = True
except SystemExit:
    _prot_missing_ok = False
check("protected-files check skips absent files", _prot_missing_ok)

# --- the honest limit: 0600 does NOT stop a same-UID process ---
_probe = tmp / "same_uid_probe"
_probe.write_text("original")
_os.chmod(_probe, 0o600)
_probe.write_text("rewritten by the same user")  # no privilege needed
_same_uid_wins = _probe.read_text() == "rewritten by the same user"
check("0600 does not stop a same-UID rewrite (documented limit)",
      _same_uid_wins)

# --- the documented claims exist in SECURITY.md ---
check("SECURITY.md records the item-10 verification",
      "What actually protects the signer" in secmd
      and "same-UID process" in secmd)
check("SECURITY.md never claims 0600 stops same-UID",
      "is not a boundary between you and software running as you"
      in " ".join(secmd.split()))

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} v0.6.0 checks passed")
sys.exit(1 if n_fail else 0)
