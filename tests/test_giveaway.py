#!/usr/bin/env python3
"""Friday community giveaway tests — no network (all XRPL calls faked).

Run: python3 tests/test_giveaway.py

Covers: giveaway.json defaults + 0600 + override validation, opt-in
payment recognition (valid/invalid tag and amount, wrong result,
unvalidated, wrong type, donation-wallet self-pay), earliest-opt-in
tracking across marker pages, opt-in exclusion from wallet-activity
counts, eligibility filtering, deterministic draw (formula locked,
empty-input error), ledger-hash wait (no-wait + timeout), destination
allowlist mutation (no policy / dedupe / 0600), the opt-in flow's three
branches (already on-ledger records opt-in; otherwise proposes and does
NOT record; short-circuits), and the entrants/draw/status commands.
"""
import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
from contextlib import redirect_stdout
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
T = load(BIN / "xrpl-trade", "xrpl_trade_gw")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.models.requests import (AccountInfo, AccountLines, AccountNFTs,  # noqa: E402
                                  AccountTx, Ledger)
from xrpl.wallet import Wallet  # noqa: E402

TMP = Path(tempfile.mkdtemp(prefix="xrpl_giveaway_test_"))
C.PROFILE_PATH = TMP / "profile.json"
C.GIVEAWAY_PATH = TMP / "giveaway.json"
C.POLICY_PATH = TMP / "policy.json"

DW = Wallet.create().classic_address      # donation wallet under test
A1 = Wallet.create().classic_address      # entrant: opt-in + activity
A2 = Wallet.create().classic_address      # entrant: opt-in only (ineligible)
A3 = Wallet.create().classic_address      # entrant: opt-in + activity
USER = Wallet.create().classic_address    # configured wallet for opt-in flow
ISS = Wallet.create().classic_address     # token issuer for status lines
TAG = 777


def fresh():
    for p in (C.PROFILE_PATH, C.GIVEAWAY_PATH, C.POLICY_PATH):
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
    """Ledger double. account_tx maps account -> list of pages (lists of
    entries); pages are chained with numeric markers. Marker-paged NFT
    inventory works the same way."""

    def __init__(self, tx_pages=None, ledger_index=100, ledger_hashes=None,
                 account_data=None, lines=None, nft_pages=None, fail=False):
        self.tx_pages = tx_pages or {}
        self.ledger_index = ledger_index
        self.ledger_hashes = ledger_hashes or {}
        self.account_data = account_data or {}
        self.lines = lines or []
        self.nft_pages = nft_pages or []
        self.fail = fail

    def request(self, req):
        if self.fail:
            return StubResp(False, {"error": "simulatedFailure"})
        if isinstance(req, AccountTx):
            pages = self.tx_pages.get(req.account, [])
            i = int(req.marker) if getattr(req, "marker", None) else 0
            page = pages[i] if i < len(pages) else []
            res = {"transactions": page}
            if i + 1 < len(pages):
                res["marker"] = str(i + 1)
            return StubResp(True, res)
        if isinstance(req, Ledger):
            if req.ledger_index == "validated":
                return StubResp(True, {"ledger_index": self.ledger_index, "validated": True})
            h = self.ledger_hashes.get(req.ledger_index)
            if h:
                return StubResp(True, {"ledger_hash": h,
                                       "ledger_index": req.ledger_index})
            return StubResp(False, {"error": "lgrNotFound"})
        if isinstance(req, AccountInfo):
            return StubResp(True, {"account_data": self.account_data})
        if isinstance(req, AccountLines):
            return StubResp(True, {"lines": self.lines})
        if isinstance(req, AccountNFTs):
            i = int(req.marker) if getattr(req, "marker", None) else 0
            page = self.nft_pages[i] if i < len(self.nft_pages) else []
            # P1-4: inventory lookups require validated ledger data.
            res = {"account_nfts": page, "validated": True}
            if i + 1 < len(self.nft_pages):
                res["marker"] = str(i + 1)
            return StubResp(True, res)
        raise AssertionError(f"unexpected request type {type(req)}")


# ---------- config ----------

fresh()
cfg = C.load_giveaway_config()
check("giveaway config defaults to Musegives wallet",
      cfg["donation_wallet"] == "rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB")
check("giveaway config defaults tag 777", cfg["opt_in_tag"] == 777)
check("giveaway.json is 0600", mode(C.GIVEAWAY_PATH) == "0o600")

cfg2 = C.load_giveaway_config(DW)
check("donation-wallet override wins", cfg2["donation_wallet"] == DW
      and cfg2["opt_in_tag"] == 777)
check("override leaves the file's default alone",
      json.loads(C.GIVEAWAY_PATH.read_text())["donation_wallet"]
      == "rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB")

try:
    C.load_giveaway_config("not-an-address")
    check("invalid --donation-wallet exits", False)
except SystemExit:
    check("invalid --donation-wallet exits", True)

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps({"donation_wallet": "bogus",
                                       "opt_in_tag": 777}))
try:
    C.load_giveaway_config()
    check("bad wallet in giveaway.json exits", False)
except SystemExit:
    check("bad wallet in giveaway.json exits", True)

fresh()
C.GIVEAWAY_PATH.write_text(json.dumps({"donation_wallet": DW,
                                       "opt_in_tag": "seven"}))
try:
    C.load_giveaway_config()
    check("bad tag in giveaway.json exits", False)
except SystemExit:
    check("bad tag in giveaway.json exits", True)

# ---------- opt-in recognition (pure) ----------

good = entry("h1", A1, DW, "1", 777)
check("valid opt-in recognized", C.is_opt_in_payment(good, DW, 777))
check("wrong tag rejected", not C.is_opt_in_payment(entry("h", A1, DW, "1", 778), DW, 777))
check("missing tag rejected", not C.is_opt_in_payment(entry("h", A1, DW, "1", None), DW, 777))
check("2 drops rejected", not C.is_opt_in_payment(entry("h", A1, DW, "2", 777), DW, 777))
check("zero amount rejected", not C.is_opt_in_payment(entry("h", A1, DW, "0", 777), DW, 777))
check("unvalidated rejected",
      not C.is_opt_in_payment(entry("h", A1, DW, "1", 777, validated=False), DW, 777))
check("failed tx rejected",
      not C.is_opt_in_payment(entry("h", A1, DW, "1", 777, result="tecPATH_DRY"), DW, 777))
check("non-payment rejected",
      not C.is_opt_in_payment(entry("h", A1, DW, "1", 777, ttype="NFTokenMint"), DW, 777))
check("donation wallet self-pay rejected",
      not C.is_opt_in_payment(entry("h", DW, DW, "1", 777), DW, 777))
check("issued-currency amount rejected",
      not C.is_opt_in_payment({"hash": "h", "validated": True,
                               "tx": {"TransactionType": "Payment",
                                      "Account": A1, "Destination": DW,
                                      "DestinationTag": 777,
                                      "Amount": {"currency": "USD",
                                                 "issuer": ISS,
                                                 "value": "1"}},
                               "meta": {"TransactionResult": "tesSUCCESS"}},
                              DW, 777))

# ---------- opt-in scan: marker pages, earliest hash wins ----------

dw_pages = [
    [entry("hA1_new", A1, DW, "1", 777),
     entry("hX1", A2, DW, "1", 778),          # wrong tag
     entry("hA3", A3, DW, "1", 777)],
    [entry("hA1_old", A1, DW, "1", 777),       # A1's earlier opt-in
     entry("hX2", A2, DW, "2", 777),          # wrong amount
     entry("hSelf", DW, DW, "1", 777)],       # self-pay: not an entrant
]
client = FakeClient(tx_pages={DW: dw_pages})
opt_ins, problem = C.scan_opt_ins(client, DW, 777)
check("scan finds opt-ins, no problem", problem is None and opt_ins is not None)
check("scan keeps earliest opt-in hash per address",
      opt_ins == {A1: "hA1_old", A3: "hA3"})

# ---------- find_opt_in_tx ----------

user_pages = [[entry("u_new", USER, DW, "1", 777)],
              [entry("u_old", USER, DW, "1", 777)]]
client = FakeClient(tx_pages={USER: user_pages})
found, problem = C.find_opt_in_tx(client, USER, DW, 777)
check("find_opt_in_tx returns earliest hash", found == "u_old" and problem is None)

client = FakeClient(tx_pages={USER: [[]]})
found, problem = C.find_opt_in_tx(client, USER, DW, 777)
check("find_opt_in_tx returns None when absent", found is None and problem is None)

# ---------- activity counting: opt-in excluded, only real actions ----------

a1_pages = [[
    entry("hA1_old", A1, DW, "1", 777),                       # the opt-in
    entry("oc1", A1, None, None, None, ttype="OfferCreate"),  # activity
    entry("pay1", A1, A3, "500", None),                       # activity
    entry("bad1", A1, A3, "500", None, result="tecPATH_DRY"),  # failed: no
    entry("unv1", A1, A3, "500", None, validated=False),      # unvalidated: no
    entry("in1", A3, A1, "500", None),                        # inbound: no
    entry("mint1", A1, None, None, None, ttype="NFTokenMint",
          result="tesSUCCESS"),
]]
client = FakeClient(tx_pages={A1: a1_pages})
n, problem = C.count_wallet_actions(client, A1, exclude_hashes=("hA1_old",))
check("activity count = 3 (offer+payment+mint), opt-in/fail/unval/inbound excluded",
      n == 3 and problem is None)

# ---------- eligibility ----------

a2_pages = [[entry("hA2", A2, DW, "1", 777)]]  # opt-in only -> ineligible
a3_pages = [[entry("hA3", A3, DW, "1", 777),
             entry("ts1", A3, None, None, None, ttype="TrustSet")]]
client = FakeClient(tx_pages={DW: [[entry("hA1_old", A1, DW, "1", 777),
                                    entry("hA2", A2, DW, "1", 777),
                                    entry("hA3", A3, DW, "1", 777)]],
                             A1: a1_pages, A2: a2_pages, A3: a3_pages})
entrants, problem = C.eligible_entrants(client, DW, 777)
by_addr = {e["address"]: e for e in entrants}
check("eligibility: problem-free scan", problem is None and len(entrants) == 3)
check("active entrant eligible", by_addr[A1]["eligible"] and by_addr[A1]["action_count"] == 3)
check("opt-in-only entrant ineligible",
      not by_addr[A2]["eligible"] and by_addr[A2]["action_count"] == 0)
check("trustset counts as activity", by_addr[A3]["eligible"])
check("entrants sorted by address",
      [e["address"] for e in entrants] == sorted(by_addr))
check("opt-in tx recorded on each entrant", by_addr[A1]["opt_in_tx"] == "hA1_old")

# ---------- deterministic draw ----------

eligible = [e for e in entrants if e["eligible"]]
LHASH = "AB" * 32
idx1, digest1, seed1 = C.pick_giveaway_winner(eligible, LHASH)
idx2, digest2, _ = C.pick_giveaway_winner(eligible, LHASH)
check("draw is deterministic", idx1 == idx2 and digest1 == digest2)
check("draw index in range", 0 <= idx1 < len(eligible))
ordered = sorted(eligible, key=lambda e: e["address"])
expected_seed = LHASH + ":" + ",".join(e["opt_in_tx"] for e in ordered)
check("draw formula locked: sha256(ledger_hash + ':' + opt-in hashes in address order)",
      seed1 == expected_seed
      and digest1 == hashlib.sha256(expected_seed.encode()).hexdigest()
      and idx1 == int(digest1, 16) % len(eligible))
try:
    C.pick_giveaway_winner([], LHASH)
    check("empty entrants raises", False)
except ValueError:
    check("empty entrants raises", True)

# ---------- ledger hash wait ----------

client = FakeClient(ledger_index=100, ledger_hashes={100: LHASH})
h, problem = C.wait_for_ledger_hash(client, 100)
check("already-validated ledger returns hash without waiting",
      h == LHASH and problem is None)
h, problem = C.wait_for_ledger_hash(client, 200, timeout=0, poll=0)
check("future ledger times out with a clear problem",
      h is None and problem and "timed out" in problem)

# ---------- destination allowlist ----------

fresh()
check("allowlist add fails closed with no policy",
      C.add_destination_allowlist_entry(DW, 777) is not None
      and "init-policy" in C.add_destination_allowlist_entry(DW, 777))

fresh()
C.POLICY_PATH.write_text(json.dumps({"policy_version": C.POLICY_VERSION,
                                     "destination_allowlist": []}))
os.chmod(C.POLICY_PATH, 0o600)
check("allowlist add works", C.add_destination_allowlist_entry(DW, 777) is None)
pol = json.loads(C.POLICY_PATH.read_text())
check("allowlist entry is exact (address, tag)",
      pol["destination_allowlist"] == [{"address": DW, "destination_tag": 777}])
check("allowlist add is idempotent",
      C.add_destination_allowlist_entry(DW, 777) is None
      and len(json.loads(C.POLICY_PATH.read_text())["destination_allowlist"]) == 1)
check("policy file is 0600 after edit", mode(C.POLICY_PATH) == "0o600")

# ---------- opt-in flow: already on-ledger -> recorded ----------

fresh()
C.POLICY_PATH.write_text(json.dumps({"policy_version": C.POLICY_VERSION,
                                     "destination_allowlist": []}))
os.chmod(C.POLICY_PATH, 0o600)
prof = C.default_profile()
cfg_cli = {"address": USER, "network": "testnet"}
gw = C.load_giveaway_config(DW)
client = FakeClient(tx_pages={USER: [[entry("u_hash", USER, DW, "1", 777)]]})
buf = io.StringIO()
with redirect_stdout(buf):
    msg = T.giveaway_opt_in_flow(cfg_cli, client, prof, gw)
check("on-ledger opt-in is confirmed in text", "already on-ledger" in msg)
check("on-ledger opt-in recorded in profile",
      prof["giveaway"] == {"opt_in": True, "opt_in_tx": "u_hash"})
saved = json.loads(C.PROFILE_PATH.read_text())
check("confirmed opt-in persisted 0600",
      saved["giveaway"] == {"opt_in": True, "opt_in_tx": "u_hash"}
      and mode(C.PROFILE_PATH) == "0o600")

# ---------- opt-in flow: not on-ledger -> proposes, does NOT record ----------

fresh()
C.POLICY_PATH.write_text(json.dumps({"policy_version": C.POLICY_VERSION,
                                     "destination_allowlist": []}))
os.chmod(C.POLICY_PATH, 0o600)
prof = C.default_profile()
gw = C.load_giveaway_config(DW)
client = FakeClient(tx_pages={USER: [[]]})  # no opt-in anywhere
proposed = {}


def fake_propose(tx, client_arg, cfg_arg, kind, summary_lines):
    proposed["tx"] = tx
    proposed["kind"] = kind
    return "deadbeef" * 8


orig_propose = T.propose
T.propose = fake_propose
try:
    buf = io.StringIO()
    with redirect_stdout(buf):
        msg = T.giveaway_opt_in_flow(cfg_cli, client, prof, gw)
finally:
    T.propose = orig_propose
tx = proposed["tx"]
check("proposal built for the 1-drop opt-in",
      tx is not None and tx.destination == DW and tx.amount == "1"
      and tx.destination_tag == 777 and tx.account == USER)
check("proposal kind labeled", proposed["kind"] == "giveaway-opt-in")
check("allowlist got the exact pair",
      {"address": DW, "destination_tag": 777}
      in json.loads(C.POLICY_PATH.read_text())["destination_allowlist"])
check("proposal does NOT mark the profile opted in",
      prof["giveaway"] == {"opt_in": False, "opt_in_tx": None})
check("caller told to re-run after approval",
      "re-run" in msg and "approve" in msg)

# ---------- opt-in flow: short-circuits ----------

prof = C.default_profile()
prof["giveaway"] = {"opt_in": True, "opt_in_tx": "abc"}
check("already-opted-in short-circuits without network",
      "already opted in" in T.giveaway_opt_in_flow(cfg_cli, None, prof, gw))
check("no client -> guidance, no crash",
      "network client" in T.giveaway_opt_in_flow(
          cfg_cli, None, C.default_profile(), gw))
check("no configured address -> guidance, no crash",
      "setup" in T.giveaway_opt_in_flow(
          {}, FakeClient(), C.default_profile(), gw))

# ---------- commands: entrants ----------

fresh()
gw = C.load_giveaway_config(DW)
cfg_cli = {"address": USER, "network": "testnet"}
client = FakeClient(tx_pages={DW: [[entry("hA1_old", A1, DW, "1", 777),
                                    entry("hA2", A2, DW, "1", 777)]],
                             A1: a1_pages, A2: a2_pages})
buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_giveaway(ns(gw_cmd="entrants", donation_wallet=DW), cfg_cli, client)
out = buf.getvalue()
check("entrants prints the table", A1[:12] in out and "eligible yes" in out
      and "eligible no" in out and "1/2 eligible" in out)

buf = io.StringIO()
try:
    with redirect_stdout(buf):
        T.cmd_giveaway(ns(gw_cmd="entrants", donation_wallet=DW), cfg_cli,
                       FakeClient(fail=True))
    check("entrants network failure exits", False)
except SystemExit:
    check("entrants network failure exits", True)

# ---------- commands: draw ----------

fresh()
gw = C.load_giveaway_config(DW)
client = FakeClient(tx_pages={DW: [[entry("hA1_old", A1, DW, "1", 777),
                                    entry("hA3", A3, DW, "1", 777)]],
                             A1: a1_pages, A3: a3_pages},
                    ledger_index=100, ledger_hashes={100: LHASH})
buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_giveaway(ns(gw_cmd="draw", donation_wallet=DW, ledger_offset=0),
                   cfg_cli, client)
out = buf.getvalue()
entrants, _ = C.eligible_entrants(client, DW, 777)
eligible = [e for e in entrants if e["eligible"]]
exp_idx, exp_digest, _ = C.pick_giveaway_winner(eligible, LHASH)
check("draw prints selection-only banner", "selection only" in out
      and "No transaction was built" in out)
check("draw prints ledger index + hash",
      "ledger:      100" in out and LHASH in out)
check("draw prints method + digest for verification",
      "sha256" in out and exp_digest in out)
check("draw prints the deterministic winner",
      eligible[exp_idx]["address"] in out and f"winner idx:  {exp_idx}" in out)
check("draw prints entrant opt-in hashes for verification",
      "hA1_old" in out and "hA3" in out)

try:
    T.cmd_giveaway(ns(gw_cmd="draw", donation_wallet=DW, ledger_offset=-1),
                   cfg_cli, client)
    check("negative --ledger-offset exits", False)
except SystemExit:
    check("negative --ledger-offset exits", True)

buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_giveaway(ns(gw_cmd="draw", donation_wallet=DW, ledger_offset=0),
                   cfg_cli, FakeClient(tx_pages={DW: [[]]}, ledger_index=100,
                                       ledger_hashes={100: LHASH}))
check("draw with no entrants says so", "no eligible entrants" in buf.getvalue())

# ---------- commands: status ----------

nft1 = {"NFTokenID": "00" * 32, "URI": "00", "NFTokenTaxon": 1, "Flags": 8}
nft2 = {"NFTokenID": "11" * 32, "URI": "00", "NFTokenTaxon": 2, "Flags": 8}
client = FakeClient(
    account_data={"Balance": "5000000", "Account": DW},
    lines=[{"currency": "USD", "account": ISS, "balance": "25"},
           {"currency": "EUR", "account": ISS, "balance": "0"}],
    nft_pages=[[nft1], [nft2]])
buf = io.StringIO()
with redirect_stdout(buf):
    T.cmd_giveaway(ns(gw_cmd="status", donation_wallet=DW), cfg_cli, client)
out = buf.getvalue()
check("status prints XRP balance", "XRP: 5" in out)
check("status prints nonzero trustlines only",
      "trustlines with balance: 1" in out and "25 USD" in out
      and "EUR" not in out)
check("status pages the full NFT inventory", "NFTs owned: 2" in out
      and "00" * 32 in out and "11" * 32 in out)

# ---------- summary ----------

fails = [n for n, ok in PASS if not ok]
print(f"\n{len(PASS) - len(fails)}/{len(PASS)} giveaway tests passed")
sys.exit(1 if fails else 0)
