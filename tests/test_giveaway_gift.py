#!/usr/bin/env python3
"""Giveaway gift (P2) tests — no network (all XRPL calls faked).

Run: python3 tests/test_giveaway_gift.py

Covers: giveaway.json max_gift_xrp/network defaults + validation, gift
destination validation (seed refusal, bad checksum, self-gift), the XRP
cap, pure gift builders (Payment XRP/IOU, 0-XRP NFT transfer offer),
signer payment-destination checks (allowlist vs giveaway mode), the
giveaway policy defaults + 0600 + no-overwrite, seed roundtrip
(write/read 0600), `giveaway setup` (getpass never echoed, seed never in
stdout, wrong-seed refused), the giveaway sign command (no seed in it),
signer load_seed (env wins, giveaway.json fallback, clear failure), the
`gift` command (cap enforcement, seed refusal, entrant warning,
NFT ownership, amount/token-id exclusivity), last-draw persistence,
`announce` formatting, envelope invariants for the giveaway-gift action,
and --help flag verification for both binaries.
"""
import hashlib
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import redirect_stdout
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace as ns

BIN = Path(__file__).resolve().parent.parent / "bin"


def load(path, as_name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(as_name, str(path))
    spec = importlib.util.spec_from_loader(as_name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[as_name] = mod
    loader.exec_module(mod)
    return mod


C = load(BIN / "xrpl_common.py", "xrpl_common")
T = load(BIN / "xrpl-trade", "xrpl_trade_gwg")
S = load(BIN / "xrpl-sign", "xrpl_sign_gwg")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.models.requests import AccountNFTs, AccountTx  # noqa: E402
from xrpl.wallet import Wallet  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="xrpl_gwgift_test_"))
C.GIVEAWAY_PATH = TMP / "giveaway.json"
C.GIVEAWAY_POLICY_PATH = TMP / "giveaway_policy.json"
C.GIVEAWAY_LAST_DRAW_PATH = TMP / "giveaway_last_draw.json"
C.GIVEAWAY_STATE_PATH = TMP / "giveaway_state.json"
C.GIVEAWAY_STATE_LOCK_PATH = TMP / "giveaway_state.lock"

DW = Wallet.create()          # donation wallet under test
W1 = Wallet.create()          # eligible entrant
W2 = Wallet.create()          # stranger (not an entrant)
ISS = Wallet.create()         # IOU issuer
SEED_WALLET = Wallet.create()  # for the setup seed test


def fresh():
    for p in (C.GIVEAWAY_PATH, C.GIVEAWAY_POLICY_PATH,
              C.GIVEAWAY_LAST_DRAW_PATH):
        if p.exists():
            p.unlink()


def mode(p):
    return oct(stat.S_IMODE(os.stat(p).st_mode))


def entry(h, acct, dest, amount, tag, ttype="Payment", result="tesSUCCESS",
          validated=True):
    e = {"hash": h, "ledger_index": 100, "validated": validated,
         "tx": {"TransactionType": ttype, "Account": acct,
                "Destination": dest, "Amount": amount},
         "meta": {"TransactionResult": result}}
    if tag is not None:
        e["tx"]["DestinationTag"] = tag
    return e


class StubResp:
    def __init__(self, ok, result):
        self._ok = ok
        self.result = result

    def is_successful(self):
        return self._ok


class FakeClient:
    def __init__(self, tx_pages=None, nft_pages=None):
        self.tx_pages = tx_pages or {}
        self.nft_pages = nft_pages or []

    def request(self, req):
        if isinstance(req, AccountTx):
            pages = self.tx_pages.get(req.account, [])
            i = int(req.marker) if getattr(req, "marker", None) else 0
            page = pages[i] if i < len(pages) else []
            res = {"transactions": page}
            if i + 1 < len(pages):
                res["marker"] = str(i + 1)
            return StubResp(True, res)
        if isinstance(req, AccountNFTs):
            i = int(req.marker) if getattr(req, "marker", None) else 0
            page = self.nft_pages[i] if i < len(self.nft_pages) else []
            res = {"account_nfts": page, "validated": True}
            if i + 1 < len(self.nft_pages):
                res["marker"] = str(i + 1)
            return StubResp(True, res)
        raise AssertionError(f"unexpected request type {type(req)}")


# ---------- config: max_gift_xrp + network ----------

fresh()
gw = C.load_giveaway_config()
check("max_gift_xrp defaults to Decimal 10",
      gw["max_gift_xrp"] == Decimal("10"))
check("giveaway network defaults to mainnet", gw["network"] == "mainnet")

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps({"donation_wallet": DW.classic_address,
                                       "max_gift_xrp": 25}))
gw = C.load_giveaway_config()
check("max_gift_xrp honored from file", gw["max_gift_xrp"] == Decimal("25"))

for bad in ("lots", -5, 0, "NaN"):
    fresh()
    C.GIVEAWAY_PATH.write_text(json.dumps({"donation_wallet": DW.classic_address,
                                           "max_gift_xrp": bad}))
    try:
        C.load_giveaway_config()
        check(f"max_gift_xrp={bad!r} exits", False)
    except SystemExit:
        check(f"max_gift_xrp={bad!r} exits", True)

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps({"donation_wallet": DW.classic_address,
                                       "network": "bogus"}))
try:
    C.load_giveaway_config()
    check("bad network exits", False)
except SystemExit:
    check("bad network exits", True)

# ---------- destination validation ----------

check("valid winner accepted",
      C.validate_gift_destination(W1.classic_address, DW.classic_address) is None)
p = C.validate_gift_destination("sEd7abcXYZ123seed", DW.classic_address)
check("seed-like --to gets the STOP refusal",
      p is not None and p.startswith("STOP"))
p = C.validate_gift_destination("rNOTANADDRESS", DW.classic_address)
check("bad checksum refused", p is not None and "not a valid classic" in p)
p = C.validate_gift_destination(DW.classic_address, DW.classic_address)
check("donation wallet as winner refused",
      p is not None and "yourself" in p)
check("empty winner refused",
      C.validate_gift_destination("   ", DW.classic_address) is not None)

# ---------- cap ----------

check("XRP at the cap passes",
      C.check_gift_cap(Decimal("10"), "XRP", Decimal("10")) is None)
p = C.check_gift_cap(Decimal("10.000001"), "XRP", Decimal("10"))
check("XRP over the cap refused with raise-it-deliberately message",
      p is not None and "max_gift_xrp" in p and "deliberately" in p)
check("IOU not subject to the XRP cap",
      C.check_gift_cap(Decimal("999999"), "USD", Decimal("10")) is None)

# ---------- pure builders ----------

pay = T.build_gift_payment(DW.classic_address, W1.classic_address,
                           Decimal("5"), "XRP", None)
d = pay.to_xrpl()
check("XRP gift: Account is the donation wallet",
      d["Account"] == DW.classic_address)
check("XRP gift: destination + 5M drops",
      d["Destination"] == W1.classic_address and d["Amount"] == "5000000")

pay = T.build_gift_payment(DW.classic_address, W1.classic_address,
                           Decimal("2.5"), "USD", ISS.classic_address)
d = pay.to_xrpl()
check("IOU gift carries currency+issuer",
      d["Amount"]["currency"] == "USD"
      and d["Amount"]["issuer"] == ISS.classic_address
      and d["Amount"]["value"] == "2.5")

NID = "00" * 32
off = T.build_gift_nft_offer(DW.classic_address, W1.classic_address, NID)
d = off.to_xrpl()
check("NFT gift: 0-drops transfer offer from the donation wallet",
      d["Account"] == DW.classic_address and d["Amount"] == "0"
      and d["Destination"] == W1.classic_address
      and d["NFTokenID"] == NID and int(d["Flags"]) & 1)
check("NFT gift: bounded expiry", d["Expiration"] > 0)

# ---------- signer destination checks (pure) ----------

strict = {"destination_allowlist":
          [{"address": W1.classic_address, "destination_tag": None}]}
gwpol = {"allow_any_payment_destination": True}
tx = {"Destination": W1.classic_address, "DestinationTag": None}
check("allowlist mode: listed destination passes",
      C.check_payment_destination(tx, strict) == [])
check("allowlist mode: unlisted destination denied",
      len(C.check_payment_destination(
          {"Destination": W2.classic_address}, strict)) == 1)
check("giveaway mode: any valid address passes",
      C.check_payment_destination({"Destination": W2.classic_address},
                                   gwpol) == [])
check("giveaway mode: garbage denied",
      len(C.check_payment_destination({"Destination": "nope"}, gwpol)) == 1)
check("giveaway mode: seed-like denied (not a valid address)",
      len(C.check_payment_destination(
          {"Destination": "sEd7" + "a" * 30}, gwpol)) == 1)

# ---------- giveaway policy ----------

fresh()
pol = C.default_giveaway_policy(Decimal("10"), "mainnet")
check("policy is marked giveaway", pol.get("giveaway") is True)
check("policy network_lock mainnet", pol["network_lock"] == "mainnet")
check("policy allows only Payment + NFTokenCreateOffer",
      pol["allowed_tx_types"] == ["Payment", "NFTokenCreateOffer"])
check("policy XRP per-tx == max_gift_xrp",
      pol["spend_limits"]["XRP"]["per_tx"] == "10")
check("policy allows any payment destination",
      pol.get("allow_any_payment_destination") is True)
check("policy version current",
      pol["policy_version"] == C.POLICY_VERSION)

check("write_giveaway_policy writes once", C.write_giveaway_policy(
    Decimal("10"), "mainnet") is True)
check("giveaway policy is 0600", mode(C.GIVEAWAY_POLICY_PATH) == "0o600")
check("write_giveaway_policy never overwrites",
      C.write_giveaway_policy(Decimal("99"), "mainnet") is False
      and json.loads(C.GIVEAWAY_POLICY_PATH.read_text())
      ["spend_limits"]["XRP"]["per_tx"] == "10")

# ---------- seed roundtrip (never printed) ----------

fresh()
C.write_giveaway_seed(SEED_WALLET.seed)
check("seed file is 0600", mode(C.GIVEAWAY_PATH) == "0o600")
check("seed roundtrips", C.read_giveaway_seed() == SEED_WALLET.seed)
fresh()
check("no seed -> None", C.read_giveaway_seed() is None)

# ---------- `giveaway setup` ----------

import getpass  # noqa: E402

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps(
    {"donation_wallet": SEED_WALLET.classic_address}))
real_getpass = getpass.getpass
getpass.getpass = lambda prompt="": SEED_WALLET.seed
buf = io.StringIO()
try:
    with redirect_stdout(buf):
        T.cmd_giveaway_setup(ns(), C.load_giveaway_config())
finally:
    getpass.getpass = real_getpass
out = buf.getvalue()
check("setup writes the policy", C.GIVEAWAY_POLICY_PATH.exists())
check("setup stores the seed", C.read_giveaway_seed() == SEED_WALLET.seed)
check("setup never echoes the seed", SEED_WALLET.seed not in out)

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps(
    {"donation_wallet": SEED_WALLET.classic_address}))
OTHER = Wallet.create()
getpass.getpass = lambda prompt="": OTHER.seed  # derives the wrong wallet
try:
    with redirect_stdout(io.StringIO()):
        T.cmd_giveaway_setup(ns(), C.load_giveaway_config())
    check("wrong-wallet seed refused", False)
except SystemExit as e:
    check("wrong-wallet seed refused", "nothing was stored" in str(e))
finally:
    getpass.getpass = real_getpass
check("refused seed not stored", C.read_giveaway_seed() is None)

getpass.getpass = lambda prompt="": ""  # Enter = skip, use the vault
buf = io.StringIO()
try:
    with redirect_stdout(buf):
        T.cmd_giveaway_setup(ns(), C.load_giveaway_config())
finally:
    getpass.getpass = real_getpass
check("skipping the seed is the vault path",
      "vault" in buf.getvalue().lower()
      and C.read_giveaway_seed() is None)

# ---------- sign command + signer seed loading ----------

h = "ab" * 32
cmd = C.giveaway_sign_command(h)
check("sign command names the giveaway seed env",
      "--seed-env XRPL_GIVEAWAY_SEED" in cmd)
check("sign command names the giveaway policy",
      "--policy" in cmd and "giveaway_policy.json" in cmd)
check("sign command carries the hash prefix", h[:16] in cmd)
check("sign command contains no seed", "sEd" not in cmd)

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps(
    {"donation_wallet": DW.classic_address, "seed": SEED_WALLET.seed}))
saved_env = dict(os.environ)
os.environ.pop(C.GIVEAWAY_SEED_ENV, None)
os.environ.pop("XRPL_SEED", None)
try:
    check("signer falls back to giveaway.json seed",
          S.load_seed(("env", C.GIVEAWAY_SEED_ENV)) == SEED_WALLET.seed)
    os.environ[C.GIVEAWAY_SEED_ENV] = "sEd111ENVSEED"
    check("env wins over the file",
          S.load_seed(("env", C.GIVEAWAY_SEED_ENV)) == "sEd111ENVSEED")
    del os.environ[C.GIVEAWAY_SEED_ENV]
    fresh()
    try:
        S.load_seed(("env", C.GIVEAWAY_SEED_ENV))
        check("missing seed exits", False)
    except SystemExit as e:
        check("missing seed exits", "vault" in str(e).lower())
    try:
        S.load_seed(("env", "XRPL_SEED"))
        check("main seed still env-only", False)
    except SystemExit as e:
        check("main seed still env-only", "XRPL_SEED" in str(e))
finally:
    os.environ.clear()
    os.environ.update(saved_env)

# ---------- `gift` command (propose mocked, client faked) ----------

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps(
    {"donation_wallet": DW.classic_address, "network": "mainnet",
     "max_gift_xrp": 10}))
gw = C.load_giveaway_config()

opt_page = [[entry("opt1", W1.classic_address, DW.classic_address, "1", 777)]]
act_page = [[entry("act1", W1.classic_address, W2.classic_address, "1000", None)]]
fake = FakeClient(tx_pages={DW.classic_address: opt_page,
                            W1.classic_address: act_page},
                  nft_pages=[[{"NFTokenID": NID}]])

proposed = {}
T.get_client = lambda network: fake
T.propose = lambda tx, client, cfg, action, lines: proposed.update(
    tx=tx, cfg=cfg, action=action, lines=lines)


def gift_args(**kw):
    base = dict(to=W1.classic_address, amount="5", ccy="XRP", issuer=None,
                token_id=None, donation_wallet=None, expires_in=86400)
    base.update(kw)
    return ns(**base)


def run_gift(**kw):
    proposed.clear()
    buf = io.StringIO()
    with redirect_stdout(buf):
        T.cmd_giveaway_gift(gift_args(**kw), gw, DW.classic_address)
    return buf.getvalue()


out = run_gift()
check("XRP gift proposes with the giveaway-gift action",
      proposed.get("action") == C.GIFT_ACTION)
check("XRP gift tx from the donation wallet",
      proposed["tx"].to_xrpl()["Account"] == DW.classic_address)
check("XRP gift proposal on the giveaway network",
      proposed["cfg"]["network"] == "mainnet")
check("eligible winner: no warning", "WARNING" not in out)

out = run_gift(to=W2.classic_address)
check("stranger winner warns but still proposes",
      "WARNING" in out and proposed.get("action") == C.GIFT_ACTION)

try:
    run_gift(amount="10.000001")
    check("gift over the cap exits", False)
except SystemExit as e:
    check("gift over the cap exits", "max_gift_xrp" in str(e))

try:
    run_gift(to="sEd7" + "b" * 30)
    check("seed-like winner exits loud", False)
except SystemExit as e:
    check("seed-like winner exits loud", str(e).startswith("STOP"))

try:
    run_gift(to=DW.classic_address)
    check("self-gift exits", False)
except SystemExit:
    check("self-gift exits", True)

try:
    run_gift(amount="5", token_id=NID)
    check("amount+token-id exits", False)
except SystemExit:
    check("amount+token-id exits", True)

try:
    run_gift(amount=None, token_id=None)
    check("neither amount nor token-id exits", False)
except SystemExit:
    check("neither amount nor token-id exits", True)

out = run_gift(amount=None, token_id=NID)
check("owned NFT proposes a 0-XRP transfer",
      proposed["tx"].to_xrpl()["Amount"] == "0"
      and proposed["tx"].to_xrpl()["Destination"] == W1.classic_address)

fake_broke = FakeClient(tx_pages={DW.classic_address: opt_page,
                                  W1.classic_address: act_page},
                        nft_pages=[[{"NFTokenID": "ff" * 32}]])
T.get_client = lambda network: fake_broke
try:
    run_gift(amount=None, token_id=NID)
    check("unowned NFT exits", False)
except SystemExit as e:
    check("unowned NFT exits", "does not own" in str(e))
T.get_client = lambda network: fake

out = run_gift(amount="3", ccy="USD", issuer=ISS.classic_address)
d = proposed["tx"].to_xrpl()
check("IOU gift proposes with issuer",
      d["Amount"]["currency"] == "USD"
      and d["Amount"]["issuer"] == ISS.classic_address)
check("IOU gift notes the policy spend-limit need",
      any("spend_limits" in ln for ln in proposed["lines"])
      and any("approved token allowlist" in ln for ln in proposed["lines"]))

try:
    run_gift(amount="3", ccy="USD", issuer=None)
    check("IOU without issuer exits", False)
except SystemExit:
    check("IOU without issuer exits", True)

# the seed must never appear in gift output
check("no seed in gift output", SEED_WALLET.seed not in out)

# ---------- last draw + announce ----------

fresh()
check("no draw on record -> None", C.load_last_draw() is None)
rec = {"drawn_at": 123, "network": "mainnet",
       "donation_wallet": DW.classic_address, "ledger_index": 999,
       "ledger_hash": "DEADBEEF" * 8,
       "method": "sha256(ledger_hash + ':' + opt-in tx hashes in "
                 "address order) mod entrants",
       "digest": "CAFE" * 16, "winner_index": 0,
       "winner": W1.classic_address, "entrant_count": 7,
       "opt_in_txs": {W1.classic_address: "opt1"}}
C.save_last_draw(rec)
check("last-draw file is 0600", mode(C.GIVEAWAY_LAST_DRAW_PATH) == "0o600")
check("last-draw roundtrips", C.load_last_draw()["winner"] == W1.classic_address)

buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_giveaway_announce(
        ns(winner=None, prize="5 XRP", donation_wallet=None), gw)
out = buf.getvalue()
for needle, name in ((W1.classic_address, "announce names the winner"),
                     ("5 XRP", "announce names the prize"),
                     (rec["ledger_hash"], "announce carries the ledger hash"),
                     ("sha256", "announce carries the method"),
                     (DW.classic_address, "announce carries the pot address"),
                     ("7:37", "announce carries the draw time")):
    check(name, needle in out)

buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_giveaway_announce(
        ns(winner=W2.classic_address, prize="an NFT", donation_wallet=None),
        gw)
check("announce --winner overrides", W2.classic_address in buf.getvalue())

fresh()
try:
    with redirect_stdout(io.StringIO()):
        T.cmd_giveaway_announce(
            ns(winner=None, prize="5 XRP", donation_wallet=None), gw)
    check("announce with no draw exits", False)
except SystemExit:
    check("announce with no draw exits", True)

# ---------- envelope invariants ----------

now = int(time.time())
base_prop = {"account": DW.classic_address, "created_at": now}
pay_tx = {"TransactionType": "Payment", "Account": DW.classic_address,
          "Fee": "12", "Sequence": 1, "LastLedgerSequence": 200}
nft_tx = dict(pay_tx, TransactionType="NFTokenCreateOffer")
C.verify_envelope_invariants(dict(base_prop, action="giveaway-gift"), pay_tx)
check("Payment + giveaway-gift passes invariants", True)
C.verify_envelope_invariants(dict(base_prop, action="giveaway-gift"), nft_tx)
check("NFTokenCreateOffer + giveaway-gift passes invariants", True)
try:
    C.verify_envelope_invariants(
        dict(base_prop, action="giveaway-gift"),
        dict(pay_tx, TransactionType="OfferCreate"))
    check("OfferCreate + giveaway-gift rejected", False)
except C.ProposalError:
    check("OfferCreate + giveaway-gift rejected", True)

# ---------- --help flag verification (both binaries) ----------

env = dict(os.environ, PYTHONPATH=os.path.expanduser(
    "~/workspace/tools/xrpl-pkgs") + ":" + str(BIN))
r = subprocess.run([sys.executable, str(BIN / "xrpl-trade"),
                    "giveaway", "gift", "--help"],
                   capture_output=True, text=True, env=env)
for f in ("--to", "--amount", "--ccy", "--issuer", "--token-id",
          "--donation-wallet", "--expires-in"):
    check(f"gift --help documents {f}", f in r.stdout)
r = subprocess.run([sys.executable, str(BIN / "xrpl-sign"), "--help"],
                   capture_output=True, text=True, env=env)
check("sign --help documents --seed-env", "--seed-env" in r.stdout)
check("sign --help documents --policy", "--policy" in r.stdout)

# ---------- summary ----------

fails = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} giveaway-gift tests passed")
sys.exit(1 if fails else 0)
