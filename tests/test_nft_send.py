#!/usr/bin/env python3
"""nft-send adversarial logic tests — no network. Run: python3 tests/test_nft_send.py

Covers the nft-send transfer flow: --to resolution (favorite name,
case-insensitive, vs classic address), transfer tx shape (0 drops +
Destination + sell flag), the 0-XRP carve-out in check_nft_offer (a
0-drops offer is allowed ONLY as a sell offer with a Destination;
0-amount without destination and 0-amount bids are refused), envelope
invariants for the new action, destination tampering / hash mismatch,
expiry enforcement, the TRANSFER ceremony (never described as a sale),
and spend accounting (fee only).
"""
import importlib.util
import json
import subprocess
import sys
import tempfile
import time
from argparse import Namespace
from decimal import Decimal
from pathlib import Path

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
T = load(BIN / "xrpl-trade", "xrpl_trade_nftsend")
S = load(BIN / "xrpl-sign", "xrpl_sign_nftsend")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.wallet import Wallet
from xrpl.utils import drops_to_xrp
ACCT = Wallet.create().classic_address
DEST = Wallet.create().classic_address
OTHER = Wallet.create().classic_address
NID = "AB" * 32


def transfer_tx(nid=NID, amount="0", flags=1, lifetime=3600, dest=DEST,
                seq=1, owner=None):
    tx = {"TransactionType": "NFTokenCreateOffer", "Account": ACCT,
          "NFTokenID": nid, "Amount": amount, "Flags": flags,
          "Expiration": C.ripple_time_from_now(lifetime),
          "Fee": "12", "Sequence": seq, "LastLedgerSequence": 999}
    if dest:
        tx["Destination"] = dest
    if owner:
        tx["Owner"] = owner
    return tx


def bid_tx(amount="1000000", lifetime=3600, seq=1):
    return {"TransactionType": "NFTokenCreateOffer", "Account": ACCT,
            "NFTokenID": NID, "Amount": amount, "Owner": OTHER,
            "Expiration": C.ripple_time_from_now(lifetime),
            "Fee": "12", "Sequence": seq, "LastLedgerSequence": 999}


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    C.XRPL_DIR = tmp
    C.PROPOSALS_DIR = tmp / "proposals"
    C.POLICY_PATH = tmp / "policy.json"
    C.STATE_PATH = tmp / "state.json"
    C.STATE_LOCK_PATH = tmp / "state.lock"
    C.AUDIT_PATH = tmp / "audit.log"
    C.APPROVED_PATH = tmp / "approved.json"
    C.FAVORITES_PATH = tmp / "favorites.json"
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {}}))
    base_policy = json.loads(json.dumps(C.DEFAULT_POLICY))
    base_policy["spend_limits"] = {
        "XRP": {"per_tx": "25", "per_day": "100"}}
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    def nft_denials(tx):
        pol = C.load_policy()
        return S.check_policy({"network": "testnet"}, tx, pol, None,
                              C.SpentTracker())

    def invariants_raise(action, tx):
        prop = {"account": ACCT, "action": action,
                "created_at": int(time.time()),
                "policy_version": C.POLICY_VERSION}
        try:
            C.verify_envelope_invariants(prop, tx)
            return None
        except C.ProposalError as e:
            return str(e)

    # --- 1. --to resolution (CLI level, propose stubbed: no network) ---
    captured = {}

    def fake_propose(tx, client, cfg, action, lines):
        captured.clear()
        txd = tx.to_xrpl() if hasattr(tx, "to_xrpl") else tx
        captured.update(tx=txd, action=action, lines=list(lines))
        return "f" * 64

    T.propose = fake_propose
    cfg = {"address": ACCT, "network": "testnet"}

    def send_cli(to, token_id=NID, expires_in=86400):
        captured.clear()
        args = Namespace(token_id=token_id, to=to, expires_in=expires_in)
        try:
            T.cmd_nft_send(args, cfg, None)
        except SystemExit as e:
            return f"EXIT:{e.code}"
        return captured

    C.save_favorites({"prizewinner": {"address": DEST,
                                      "added_at": 1,
                                      "last_checked_ledger": None}})

    r = send_cli("prizewinner")
    check("favorite name resolves to its address",
          isinstance(r, dict) and r["tx"]["Destination"] == DEST)
    check("favorite name shown in the proposal summary",
          isinstance(r, dict)
          and any("favorite: prizewinner" in ln for ln in r["lines"]))
    r = send_cli("PRIZEWINNER")
    check("--to favorite lookup is case-insensitive",
          isinstance(r, dict) and r["tx"]["Destination"] == DEST
          and any("favorite: prizewinner" in ln for ln in r["lines"]))
    r = send_cli(OTHER)
    check("raw classic address works directly",
          isinstance(r, dict) and r["tx"]["Destination"] == OTHER
          and not any("favorite:" in ln for ln in r["lines"]))
    r = send_cli("nosuchfriend")
    check("unknown favorite name refused",
          isinstance(r, str) and r.startswith("EXIT:")
          and "neither a favorite name" in str(r))
    r = send_cli("rBadChecksum11111111111111111111111")
    check("invalid address refused",
          isinstance(r, str) and r.startswith("EXIT:"))
    r = send_cli(DEST, token_id="AB" * 31)
    check("short token id refused", isinstance(r, str)
          and r.startswith("EXIT:"))
    r = send_cli(DEST, token_id="ZZ" * 32)
    check("non-hex token id refused", isinstance(r, str)
          and r.startswith("EXIT:"))
    r = send_cli(ACCT)
    check("sending to yourself refused",
          isinstance(r, str) and r.startswith("EXIT:"))
    C.FAVORITES_PATH.write_text(json.dumps(
        {"broken": {"address": "not-an-address"}}))
    r = send_cli("broken")
    check("favorite with corrupt address refused",
          isinstance(r, str) and r.startswith("EXIT:"))
    C.save_favorites({"prizewinner": {"address": DEST, "added_at": 1,
                                      "last_checked_ledger": None}})

    # transfer tx shape from the CLI
    r = send_cli(DEST)
    tx = r["tx"]
    check("transfer tx is NFTokenCreateOffer", isinstance(r, dict)
          and tx["TransactionType"] == "NFTokenCreateOffer")
    check("transfer Amount is 0 drops", tx["Amount"] == "0")
    check("transfer carries the sell flag",
          int(tx["Flags"]) & C.NFT_SELL_FLAG)
    check("transfer has no Owner field", "Owner" not in tx)
    check("transfer has an Expiration", "Expiration" in tx)
    check("proposal action is nft-send", r["action"] == "nft-send")
    check("summary says TRANSFER gift, not sale",
          any("TRANSFER (gift" in ln for ln in r["lines"])
          and not any("sale" in ln.lower().replace("not a sale", "")
                      for ln in r["lines"]))

    # argparse: --to is required (no network touched — parse fails first)
    import os
    env = dict(os.environ)
    env["HOME"] = str(tmp)
    env["PYTHONPATH"] = (str(Path.home() / "workspace" / "tools"
                             / "xrpl-pkgs") + os.pathsep
                         + env.get("PYTHONPATH", ""))
    p = subprocess.run(
        [sys.executable, str(BIN / "xrpl-trade"), "nft-send",
         "--token-id", NID],
        capture_output=True, text=True, env=env, timeout=60)
    check("--to missing is an argparse error",
          p.returncode == 2 and "--to" in p.stderr)

    # --- 2. signer policy: the 0-XRP carve-out ---
    d, _ = nft_denials(transfer_tx())
    check("signer allows the transfer (sell + dest + 0)",
          not d)
    d, _ = nft_denials(transfer_tx(dest=None))
    check("0-XRP offer WITHOUT destination refused",
          any("without a Destination" in x for x in d))
    pol = C.load_policy()
    pol["nft"]["allow_buy_offers"] = True
    C.POLICY_PATH.write_text(json.dumps(pol))

    def nft_denials_buy(tx):
        return S.check_policy({"network": "testnet"}, tx,
                               C.load_policy(), None, C.SpentTracker())
    d, _ = nft_denials_buy(bid_tx(amount="0"))
    check("buy offer with 0 amount refused",
          any("positive" in x for x in d))
    d, _ = nft_denials_buy(bid_tx(amount="1000000"))
    check("normal bid still allowed with toggle on", not d)
    # restore default toggle for the remaining tests
    pol["nft"]["allow_buy_offers"] = False
    C.POLICY_PATH.write_text(json.dumps(pol))

    # --- 3. envelope invariants for the new action ---
    check("nft-send matches a real transfer",
          invariants_raise("nft-send", transfer_tx()) is None)
    check("nft-send on a priced listing rejected",
          invariants_raise("nft-send",
                            transfer_tx(amount="1000000")) is not None)
    check("nft-send without destination rejected",
          invariants_raise("nft-send",
                            transfer_tx(dest=None)) is not None)
    check("nft-list on a transfer rejected (must be a priced sale)",
          invariants_raise("nft-list", transfer_tx()) is not None)
    check("nft-list still matches a priced sell offer",
          invariants_raise("nft-list",
                            transfer_tx(amount="1000000",
                                        dest=None)) is None)
    check("nft-bid on a transfer rejected",
          invariants_raise("nft-bid", transfer_tx()) is not None)
    check("nft-send on a buy offer rejected",
          invariants_raise("nft-send", bid_tx()) is not None)

    # --- 4. tampering / expiry ---
    _pdigest = C._sha256_file(C.POLICY_PATH)
    h, path = C.save_proposal(transfer_tx(), "testnet", ACCT, "nft-send",
                              profile="adhoc-testnet",
                              policy_sha256=_pdigest)
    prop = json.loads(path.read_text())
    prop["tx"]["Destination"] = OTHER  # tamper: redirect the gift
    try:
        C.verify_proposal(prop, path)
        tamper = None
    except C.ProposalError as e:
        tamper = str(e)
    check("destination tampering detected",
          tamper is not None
          and ("hash mismatch" in tamper or "tampered" in tamper))
    prop2 = json.loads(path.read_text())
    prop2["created_at"] = int(time.time()) - 10**7  # rewind the clock
    try:
        C.verify_proposal(prop2, path)
        tamper2 = None
    except C.ProposalError as e:
        tamper2 = str(e)
    check("envelope hash mismatch (created_at) refused",
          tamper2 is not None and "hash mismatch" in tamper2)

    noexp = transfer_tx()
    del noexp["Expiration"]
    d, _ = nft_denials(noexp)
    check("transfer without Expiration refused",
          any("without Expiration" in x for x in d))
    expired = transfer_tx(lifetime=-3600)
    d, _ = nft_denials(expired)
    check("expired transfer refused",
          any("outside the allowed window" in x for x in d))
    toolong = transfer_tx(lifetime=86400 * 30)
    d, _ = nft_denials(toolong)
    check("transfer expiry beyond policy max refused",
          any("outside the allowed window" in x for x in d))

    # --- 5. ceremony + spends ---
    lines = "\n".join(C.describe_tx(transfer_tx(), "nft-send"))
    check("signer ceremony says TRANSFER (gift)",
          "TRANSFER (gift" in lines)
    check("ceremony never calls it a sale",
          "sale" not in lines.lower().replace("not a sale", ""))
    check("ceremony shows the full destination address", DEST in lines)
    check("ceremony notes the recipient must accept",
          "must accept" in lines)
    spends = C.tx_spends(transfer_tx())
    check("transfer spends 0 XRP beyond the fee",
          spends["XRP"] == Decimal(drops_to_xrp("12")))
    check("transfer spends nothing else",
          set(spends) == {"XRP"})

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
