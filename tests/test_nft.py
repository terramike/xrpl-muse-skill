#!/usr/bin/env python3
"""v0.5 NFT adversarial logic tests — no network. Run: python3 tests/test_nft.py

Covers the v0.5 additions: NFTokenMint / NFTokenCreateOffer strict schemas,
mint policy (URI length/hex, TransferFee cap, flag gating, rolling mint
rate limit), listing policy (XRP-only, sell-only, bounded expiry, valid
destination), envelope invariants for the new actions, the v3->v4 policy
migration (which must NOT silently widen allowed_tx_types), and the
bring-your-own-key Pinata helper (mocked — no real key, no network).
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
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
T = load(BIN / "xrpl-trade", "xrpl_trade_v05")
S = load(BIN / "xrpl-sign", "xrpl_sign_v05")
P = load(BIN / "xrpl_pin.py", "xrpl_pin")

PASS = []


def check(name, cond):
    PASS.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name)


from xrpl.wallet import Wallet
from xrpl.utils import drops_to_xrp
ACCT = Wallet.create().classic_address
DEST = Wallet.create().classic_address

GOOD_URI = "ipfs://bafybeihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku".encode().hex().upper()


def mint_tx(uri_hex=GOOD_URI, fee=1000, flags=9, taxon=0, seq=1):
    return {"TransactionType": "NFTokenMint", "Account": ACCT,
            "NFTokenTaxon": taxon, "URI": uri_hex, "TransferFee": fee,
            "Flags": flags, "Fee": "12", "Sequence": seq,
            "LastLedgerSequence": 999}


def list_tx(nid="AB" * 32, amount="1000000", flags=1, lifetime=3600,
            dest=None, seq=1):
    tx = {"TransactionType": "NFTokenCreateOffer", "Account": ACCT,
          "NFTokenID": nid, "Amount": amount, "Flags": flags,
          "Expiration": C.ripple_time_from_now(lifetime),
          "Fee": "12", "Sequence": seq, "LastLedgerSequence": 999}
    if dest:
        tx["Destination"] = dest
    return tx


with tempfile.TemporaryDirectory() as td:
    tmp = Path(td)
    C.XRPL_DIR = tmp
    C.PROPOSALS_DIR = tmp / "proposals"
    C.POLICY_PATH = tmp / "policy.json"
    C.STATE_PATH = tmp / "state.json"
    C.STATE_LOCK_PATH = tmp / "state.lock"
    C.AUDIT_PATH = tmp / "audit.log"
    C.APPROVED_PATH = tmp / "approved.json"
    C.APPROVED_PATH.write_text(json.dumps({"pairs": {}}))
    base_policy = json.loads(json.dumps(C.DEFAULT_POLICY))
    base_policy["spend_limits"] = {
        "XRP": {"per_tx": "25", "per_day": "100"}}
    C.POLICY_PATH.write_text(json.dumps(base_policy))

    def nft_denials(tx, action):
        pol = C.load_policy()
        # NFT checks never touch the network client
        return S.check_policy({"network": "testnet"}, tx, pol, None,
                              C.SpentTracker())

    def invariants_raise(prop, tx):
        try:
            C.verify_envelope_invariants(prop, tx)
            return None
        except C.ProposalError as e:
            return str(e)

    # --- 1. version / policy shape ---
    check("policy version is 4", C.POLICY_VERSION == 4)
    check("nft section has all v0.5 keys",
          set(C.DEFAULT_POLICY["nft"]) == {"max_transfer_fee",
                                           "max_mints_per_day",
                                           "allowed_mint_flags",
                                           "max_uri_bytes",
                                           "allow_buy_offers",
                                           "max_bid_xrp"})
    check("NFT types in default allowlist",
          "NFTokenMint" in C.DEFAULT_ALLOWED_TX_TYPES
          and "NFTokenCreateOffer" in C.DEFAULT_ALLOWED_TX_TYPES
          and "NFTokenAcceptOffer" in C.DEFAULT_ALLOWED_TX_TYPES)

    # --- 2. strict schemas ---
    no_uri = mint_tx()
    del no_uri["URI"]
    check("NFTokenMint without URI flagged",
          any("URI" in p for p in C.validate_tx_shape(
              no_uri, C.DEFAULT_ALLOWED_TX_TYPES)))
    no_taxon = mint_tx()
    del no_taxon["NFTokenTaxon"]
    check("NFTokenMint without NFTokenTaxon flagged",
          any("NFTokenTaxon" in p for p in C.validate_tx_shape(
              no_taxon, C.DEFAULT_ALLOWED_TX_TYPES)))
    smuggle_issuer = mint_tx()
    smuggle_issuer["Issuer"] = DEST
    check("NFTokenMint+Issuer (mint-for-other) rejected",
          any("Issuer" in p for p in C.validate_tx_shape(
              smuggle_issuer, C.DEFAULT_ALLOWED_TX_TYPES)))
    smuggle_memo = mint_tx()
    smuggle_memo["Memos"] = [{"Memo": {"MemoData": "hi"}}]
    check("NFTokenMint+Memos rejected",
          any("Memos" in p for p in C.validate_tx_shape(
              smuggle_memo, C.DEFAULT_ALLOWED_TX_TYPES)))
    smuggle_owner = list_tx()
    smuggle_owner["Owner"] = DEST
    check("NFTokenCreateOffer+Owner (buy offer) now schema-allowed",
          not any("Owner" in p for p in C.validate_tx_shape(
              smuggle_owner, C.DEFAULT_ALLOWED_TX_TYPES)))
    check("NFTokenCreateOffer+Owner (buy offer) still policy-gated",
          any("allow_buy_offers" in d for d in C.check_nft_offer(
              smuggle_owner, C.nft_policy({}))))
    bad_nid = list_tx()
    del bad_nid["NFTokenID"]
    check("NFTokenCreateOffer without NFTokenID flagged",
          any("NFTokenID" in p for p in C.validate_tx_shape(
              bad_nid, C.DEFAULT_ALLOWED_TX_TYPES)))

    # --- 3. URI policy ---
    big_uri = ("ab" * 300).upper()
    check("URI > 256 bytes denied",
          any("256" in d for d in C.check_nft_mint(
              mint_tx(uri_hex=big_uri), base_policy)))
    check("non-hex URI denied",
          any("hex" in d for d in C.check_nft_mint(
              mint_tx(uri_hex="ZZZ"), base_policy)))
    check("empty URI denied",
          any("empty" in d for d in C.check_nft_mint(
              mint_tx(uri_hex=""), base_policy)))
    check("good URI passes", C.check_nft_mint(mint_tx(), base_policy) == [])

    # --- 4. royalty policy ---
    check("10% royalty (cap) passes",
          C.check_nft_mint(mint_tx(fee=10000), base_policy) == [])
    check("10.001% royalty denied",
          any("TransferFee" in d for d in C.check_nft_mint(
              mint_tx(fee=10001), base_policy)))
    check("negative royalty denied",
          any("TransferFee" in d for d in C.check_nft_mint(
              mint_tx(fee=-1), base_policy)))
    loose = json.loads(json.dumps(base_policy))
    loose["nft"]["max_transfer_fee"] = 60000  # operator misconfigures high
    check("protocol ceiling (50000) holds even if policy cap is higher",
          any("TransferFee" in d for d in C.check_nft_mint(
              mint_tx(fee=50001), loose)))
    check("50000 fee allowed when policy cap is 50000",
          C.check_nft_mint(mint_tx(fee=50000),
                           {**loose, "nft": {**loose["nft"],
                                             "max_transfer_fee": 50000}}) == [])

    # --- 5. flag gating ---
    check("transferable+burnable (9) passes",
          C.check_nft_mint(mint_tx(flags=9), base_policy) == [])
    check("tfOnlyXRP (2) denied by default",
          any("disallowed" in d for d in C.check_nft_mint(
              mint_tx(flags=2), base_policy)))
    check("tfMutable (16) denied by default",
          any("disallowed" in d for d in C.check_nft_mint(
              mint_tx(flags=16), base_policy)))
    check("mixed allowed+disallowed (11) denied",
          any("disallowed" in d for d in C.check_nft_mint(
              mint_tx(flags=11), base_policy)))

    # --- 6. listing policy ---
    check("sell offer without Expiration denied",
          any("Expiration" in d for d in nft_denials(
              {k: v for k, v in list_tx().items() if k != "Expiration"},
              "nft-list")[0]))
    past = list_tx(lifetime=-100)
    check("already-expired listing denied",
          any("allowed window" in d for d in nft_denials(past, "nft-list")[0]))
    far = list_tx(lifetime=86400 * 30)
    check("30-day listing denied",
          any("allowed window" in d for d in nft_denials(far, "nft-list")[0]))
    check("buy-side offer (flags=0) denied",
          any("SELL" in d for d in C.check_nft_offer(
              list_tx(flags=0), base_policy)))
    check("unknown flag bits denied",
          any("unknown" in d for d in C.check_nft_offer(
              list_tx(flags=3), base_policy)))
    iou_amt = list_tx()
    iou_amt["Amount"] = {"currency": "USD", "issuer": DEST, "value": "5"}
    check("IOU-denominated listing denied (XRP-only v1)",
          any("XRP-only" in d for d in C.check_nft_offer(iou_amt,
                                                        base_policy)))
    check("malformed NFTokenID denied",
          any("NFTokenID" in d for d in C.check_nft_offer(
              list_tx(nid="ZZZ"), base_policy)))
    check("short NFTokenID denied",
          any("NFTokenID" in d for d in C.check_nft_offer(
              list_tx(nid="AB" * 31), base_policy)))
    check("invalid destination denied",
          any("Destination" in d for d in C.check_nft_offer(
              list_tx(dest="not-an-address"), base_policy)))
    check("valid private destination passes",
          C.check_nft_offer(list_tx(dest=DEST), base_policy) == [])

    # --- 7. full policy passes for the happy paths ---
    denials, spends = nft_denials(mint_tx(), "nft-mint")
    check("valid mint passes policy", denials == [])
    check("mint spends only the fee (XRP)", set(spends) == {"XRP"})
    denials, _ = nft_denials(list_tx(), "nft-list")
    check("valid listing passes policy", denials == [])
    # no book-deviation check on listings: unique token, no fungible book
    check("listing has no price-deviation denial path",
          not any("deviat" in d for d in nft_denials(list_tx(), "nft-list")[0]))

    # --- 8. envelope invariants for the new actions ---
    h, path = C.save_proposal(mint_tx(), "testnet", ACCT, "nft-mint", profile="adhoc-testnet", policy_sha256=C._sha256_file(C.POLICY_PATH))
    prop = json.loads(path.read_text())
    check("nft-mint envelope verifies",
          invariants_raise(prop, prop["tx"]) is None)
    h2, path2 = C.save_proposal(list_tx(), "testnet", ACCT, "nft-list", profile="adhoc-testnet", policy_sha256=C._sha256_file(C.POLICY_PATH))
    prop2 = json.loads(path2.read_text())
    check("nft-list envelope verifies",
          invariants_raise(prop2, prop2["tx"]) is None)
    check("action/type mismatch rejected (buy vs NFTokenMint)",
          invariants_raise({**prop, "action": "buy"}, prop["tx"]) is not None)
    wrong_acct = json.loads(json.dumps(prop))
    wrong_acct["account"] = DEST
    check("envelope/tx account mismatch rejected (mint)",
          invariants_raise(wrong_acct, wrong_acct["tx"]) is not None)

    # --- 9. allowlist still gates the new types ---
    locked = json.loads(json.dumps(base_policy))
    locked["allowed_tx_types"] = ["OfferCreate", "OfferCancel", "TrustSet",
                                  "Payment"]
    C.POLICY_PATH.write_text(json.dumps(locked))
    denials, _ = nft_denials(mint_tx(), "nft-mint")
    check("NFTokenMint denied when not in allowed_tx_types",
          any("not in the allowlist" in d for d in denials))
    denials, _ = nft_denials(list_tx(), "nft-list")
    check("NFTokenCreateOffer denied when not in allowed_tx_types",
          any("not in the allowlist" in d for d in denials))
    C.POLICY_PATH.write_text(json.dumps(base_policy))  # restore

    # --- 10. rolling mint rate limit: atomic, concurrency-safe ---
    # The cap is enforced through SpentTracker count reservations, not the
    # audit log: check+reserve is one locked section, so parallel signers
    # cannot both slip under the cap. Pending reservations count.
    tr = C.SpentTracker()  # isolated: STATE_PATH redirected above

    check("mint rate OK when empty",
          C.check_mint_rate(base_policy, tr) == [])

    ok = True
    for _ in range(9):
        d, rid = tr.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
        ok = ok and not d and bool(rid)
    check("9 mints reserve atomically", ok)
    check("provisional check passes below the cap",
          C.check_mint_rate(base_policy, tr) == [])
    denials, _ = nft_denials(mint_tx(seq=2), "nft-mint")
    check("policy passes the 10th mint", denials == [])
    d, rid10 = tr.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    check("10th mint reserves (cap is 10)", not d and bool(rid10))

    # two racers hitting the cap at once are both denied — no overshoot
    d11a, _ = tr.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    d11b, _ = tr.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    check("11th mint denied (racer A)", bool(d11a))
    check("11th mint denied (racer B)", bool(d11b))
    check("provisional check denies at the cap",
          bool(C.check_mint_rate(base_policy, tr)))
    denials, _ = nft_denials(mint_tx(seq=3), "nft-mint")
    check("policy denies the 11th mint",
          any("exceed cap" in d for d in denials))

    # releasing one reservation frees exactly one slot
    tr.release_reservation(rid10)
    d, _ = tr.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    check("released slot is reusable", not d)

    # old CONFIRMED entries age out of the rolling window.
    # (Pending reservations never age out — P1-3: unresolved liabilities
    # persist until proven otherwise.)
    st = json.loads(C.STATE_PATH.read_text())
    for e in st["entries"]:
        e["ts"] = int(time.time()) - 90000  # 25h old
        e["status"] = "confirmed"
    C.STATE_PATH.write_text(json.dumps(st))
    check("25h-old mints no longer count",
          C.check_mint_rate(base_policy, tr) == [])

    # --- 10b. mint reservation lifecycle: confirm keeps, failure frees ---
    tr2 = C.SpentTracker(state_path=tmp / "state2.json",
                         lock_path=tmp / "state2.lock")
    d, r1 = tr2.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    check("lifecycle reservation ok", not d and bool(r1))
    tr2.bind_reservation(r1, "A" * 64, 999)
    tr2.confirm("A" * 64)  # validated tesSUCCESS
    d, _ = tr2.try_reserve_count(C.NFT_MINT_ASSET, 10, 10)
    check("confirmed mint still counts toward the cap", bool(d))
    tr2.release_tx("A" * 64)  # validated failure
    d, _ = tr2.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    check("validated-failure mint releases its slot", not d)
    # ambiguous (bound but unresolved) stays pending and counts
    d, r2 = tr2.try_reserve_count(C.NFT_MINT_ASSET, 1, 10)
    tr2.bind_reservation(r2, "B" * 64, 999)
    d, _ = tr2.try_reserve_count(C.NFT_MINT_ASSET, 10, 10)
    check("unresolved in-flight mint still counts",
          any("in the last 24h" in x and "would exceed cap" in x
              for x in d))

    # --- 11. v3 -> v4 migration is conservative ---
    v3 = json.loads(json.dumps(base_policy))
    v3["policy_version"] = 3
    del v3["nft"]
    v3["allowed_tx_types"] = ["OfferCreate", "OfferCancel", "TrustSet",
                              "Payment"]
    v3["network_lock"] = "mainnet"  # operator setting must survive
    C.POLICY_PATH.write_text(json.dumps(v3))
    S.cmd_migrate_policy(None)
    migrated = json.loads(C.POLICY_PATH.read_text())
    check("v3 migrates to v4", migrated["policy_version"] == 4)
    check("migration adds the nft defaults",
          migrated.get("nft", {}).get("max_transfer_fee") == 10000)
    check("migration does NOT widen allowed_tx_types",
          migrated["allowed_tx_types"] == ["OfferCreate", "OfferCancel",
                                           "TrustSet", "Payment"])
    check("migration preserves operator settings",
          migrated["network_lock"] == "mainnet")
    check("migration keeps a .v3.bak",
          (tmp / "policy.json.v3.bak").exists())
    # v4 backfill path
    v4bare = json.loads(json.dumps(migrated))
    del v4bare["nft"]
    C.POLICY_PATH.write_text(json.dumps(v4bare))
    S.cmd_migrate_policy(None)
    refilled = json.loads(C.POLICY_PATH.read_text())
    check("v4 backfill restores the nft section",
          refilled.get("nft", {}).get("max_mints_per_day") == 10)
    C.POLICY_PATH.write_text(json.dumps(base_policy))  # restore

    # --- 12. Pinata helper: bring-your-own-key, mocked transport ---
    # P1-4: pin sources must live inside the permitted media directory.
    # The test media dir is passed explicitly (production callers resolve
    # the protected dir from config).
    calls = []

    def fake_post(url, body, content_type, filename=None):
        calls.append((url, filename or content_type))
        return {"IpfsHash": "bafytestcid123"}

    real_post = P._post
    P._post = fake_post
    os.environ["PINATA_JWT"] = "test-jwt-not-a-real-key"
    meta = P.build_metadata("Cool Art", "A test piece", "bafyimg")
    check("metadata has XLS-24d shape",
          meta == {"name": "Cool Art", "description": "A test piece",
                   "image": "ipfs://bafyimg"})
    tmedia = tempfile.mkdtemp(prefix="xrpl-test-media-")
    with tempfile.NamedTemporaryFile(suffix=".png", dir=tmedia,
                                     delete=False) as tf:
        tf.write(b"\x89PNG\r\n\x1a\nfakepng")
        tf.flush()
        art_path = tf.name
        img_cid, meta_cid = P.pin_artwork(art_path, "Cool Art", "A test piece",
                                          media_dir=tmedia)
    check("pin_artwork returns both CIDs",
          img_cid == "bafytestcid123" and meta_cid == "bafytestcid123")
    check("art pinned as file, metadata as JSON",
          calls[0][0].endswith("pinFileToIPFS")
          and calls[1][0].endswith("pinJSONToIPFS"))
    # P1-4: a source outside the permitted media dir is refused even with
    # a valid key and valid PNG bytes.
    with tempfile.NamedTemporaryFile(suffix=".png") as outside:
        outside.write(b"\x89PNG\r\n\x1a\nfakepng")
        outside.flush()
        try:
            P.pin_file(outside.name, media_dir=tmedia)
            check("pin outside media dir is refused", False)
        except SystemExit as e:
            check("pin outside media dir is refused",
                  "outside the NFT media directory" in str(e))
    del os.environ["PINATA_JWT"]
    P._post = real_post  # real transport: must fail on the missing key
    try:
        P.pin_file(art_path, media_dir=tmedia)
        check("missing PINATA_JWT fails cleanly", False)
    except SystemExit as e:
        check("missing PINATA_JWT fails cleanly",
              "PINATA_JWT" in str(e))
    # (module is reloaded fresh on every test run; no restore needed)

    # --- 13. derived ceremony text for the new types ---
    mlines = "\n".join(C.describe_tx(mint_tx(), "nft-mint"))
    check("mint ceremony shows royalty %",
          "1.000%" in mlines and "royalty" in mlines)
    check("mint ceremony shows the URI text", "ipfs://" in mlines)
    llines = "\n".join(C.describe_tx(list_tx(), "nft-list"))
    check("listing ceremony shows price + token id",
          "1.000000 XRP" in llines and ("AB" * 32) in llines)
    check("listing ceremony marks it a SELL", "SELL" in llines)

    # --- 14. xrpl-py model round-trip (what the CLI builds) ---
    from xrpl.models.transactions import (NFTokenCreateOffer as MOffer,
                                          NFTokenCreateOfferFlag,
                                          NFTokenMint as MMint,
                                          NFTokenMintFlag)
    m = MMint(account=ACCT, nftoken_taxon=7,
              uri="697066733A2F2F62616679",
              transfer_fee=2500,
              flags=int(NFTokenMintFlag.TF_TRANSFERABLE)
              | int(NFTokenMintFlag.TF_BURNABLE))
    md = m.to_xrpl()
    check("model mint encodes Flags=9, fee, taxon",
          md["Flags"] == 9 and md["TransferFee"] == 2500
          and md["NFTokenTaxon"] == 7)
    o = MOffer(account=ACCT, nftoken_id="ab" * 32, amount="2500000",
               flags=int(NFTokenCreateOfferFlag.TF_SELL_NFTOKEN))
    od = o.to_xrpl()
    check("model sell offer encodes",
          od["Flags"] == 1 and od["Amount"] == "2500000")

    # --- 15. nft-buy / nft-bid (stub ledger, no network) ---
    from xrpl.models.requests import AccountNFTs, LedgerEntry, Ledger

    OFFER_IDX = "AB" * 32
    TOKEN = "CD" * 32

    def sell_entry(**kw):
        e = {"LedgerEntryType": "NFTokenOffer", "Flags": 1,
             "Owner": ACCT, "NFTokenID": TOKEN, "Amount": "2000000"}
        e.update(kw)
        return e

    class StubResp:
        def __init__(self, ok, result):
            self._ok = ok
            self.result = result

        def is_successful(self):
            return self._ok

    class StubClient:
        """Ledger double: one offer entry + the seller's NFT page."""
        def __init__(self, offer, nfts):
            self.offer = offer
            self.nfts = nfts

        def request(self, req):
            if isinstance(req, Ledger):
                return StubResp(True, {"ledger_index": 100, "validated": True})
            if isinstance(req, LedgerEntry):
                if self.offer is None:
                    return StubResp(False, {"error": "entryNotFound"})
                return StubResp(True, {"node": self.offer, "validated": True, "ledger_index": 100})
            if isinstance(req, AccountNFTs):
                return StubResp(True, {"account_nfts": self.nfts, "validated": True, "ledger_index": 100})
            raise AssertionError("unexpected request type")

    seller_nfts = [{"NFTokenID": TOKEN, "URI": GOOD_URI,
                    "NFTokenTaxon": 7, "Flags": 9}]
    good_client = StubClient(sell_entry(), seller_nfts)
    pol_on = json.loads(json.dumps(base_policy))
    pol_on["nft"]["allow_buy_offers"] = True

    def accept_tx(idx=OFFER_IDX):
        return {"TransactionType": "NFTokenAcceptOffer", "Account": DEST,
                "NFTokenSellOffer": idx, "Fee": "12", "Sequence": 1,
                "LastLedgerSequence": 999}

    # schema: direct mode only
    no_idx = accept_tx()
    del no_idx["NFTokenSellOffer"]
    check("NFTokenAcceptOffer without sell offer flagged",
          any("NFTokenSellOffer" in p for p in C.validate_tx_shape(
              no_idx, C.DEFAULT_ALLOWED_TX_TYPES)))
    smuggle_buy = accept_tx()
    smuggle_buy["NFTokenBuyOffer"] = "EF" * 32
    check("NFTokenAcceptOffer+NFTokenBuyOffer rejected",
          any("NFTokenBuyOffer" in p for p in C.validate_tx_shape(
              smuggle_buy, C.DEFAULT_ALLOWED_TX_TYPES)))
    smuggle_broker = accept_tx()
    smuggle_broker["NFTokenBrokerFee"] = "100"
    check("NFTokenAcceptOffer+NFTokenBrokerFee rejected",
          any("NFTokenBrokerFee" in p for p in C.validate_tx_shape(
              smuggle_broker, C.DEFAULT_ALLOWED_TX_TYPES)))
    check("NFTokenAcceptOffer direct-mode shape clean",
          not C.validate_tx_shape(accept_tx(), C.DEFAULT_ALLOWED_TX_TYPES))

    # offer verification
    d, amt = C.check_nft_accept_offer(accept_tx("xyz"), good_client, pol_on)
    check("malformed offer index refused",
          any("64 hex" in x for x in d))
    d, amt = C.check_nft_accept_offer(accept_tx(), None, base_policy)
    check("buy side disabled by default (toggle fast path, no network)",
          any("allow_buy_offers" in x for x in d))
    d, amt = C.check_nft_accept_offer(
        accept_tx(), StubClient(sell_entry(Flags=0), seller_nfts), pol_on)
    check("accepting a BUY offer refused",
          any("BUY offer" in x for x in d))
    d, amt = C.check_nft_accept_offer(
        accept_tx(), StubClient(sell_entry(Amount={"currency": "USD",
                                                  "issuer": DEST,
                                                  "value": "1"}),
                               seller_nfts), pol_on)
    check("non-XRP sell amount refused",
          any("XRP-only" in x for x in d))
    d, amt = C.check_nft_accept_offer(
        accept_tx(), StubClient(None, seller_nfts), pol_on)
    check("vanished offer refused",
          any("not on ledger" in x for x in d))
    d, amt = C.check_nft_accept_offer(
        accept_tx(), StubClient(sell_entry(), []), pol_on)
    check("seller-no-longer-owns-token refused",
          any("not found in the seller's inventory" in x for x in d))
    lines, d, amt = C.nft_sell_offer_report(good_client, OFFER_IDX)
    check("valid sell offer verifies clean",
          not d and amt == Decimal("2"))
    report = "\n".join(lines)
    check("verification shows seller + token + price + uri + taxon",
          ACCT in report and TOKEN in report and "2.000000 XRP" in report
          and "ipfs://" in report and "7" in report)

    # nft-bid (buy offer) policy
    def bid_tx(owner=DEST, amount="1000000", flags=0):
        return {"TransactionType": "NFTokenCreateOffer", "Account": ACCT,
                "NFTokenID": TOKEN, "Amount": amount, "Owner": owner,
                "Flags": flags,
                "Expiration": C.ripple_time_from_now(3600),
                "Fee": "12", "Sequence": 1, "LastLedgerSequence": 999}

    check("bid refused when buy side disabled",
          any("allow_buy_offers" in x for x in C.check_nft_offer(
              bid_tx(), base_policy)))
    check("valid bid passes with toggle on",
          not C.check_nft_offer(bid_tx(), pol_on))
    check("bid over max_bid_xrp refused",
          any("max_bid_xrp" in x for x in C.check_nft_offer(
              bid_tx(amount="20000000"), pol_on)))
    check("IOU bid refused",
          any("XRP-only" in x for x in C.check_nft_offer(
              bid_tx(amount={"currency": "USD", "issuer": DEST,
                             "value": "1"}), pol_on)))
    check("bid with sell flag refused",
          any("tfSellNFToken" in x for x in C.check_nft_offer(
              bid_tx(flags=1), pol_on)))
    no_owner = bid_tx()
    del no_owner["Owner"]
    check("ownerless flags=0 offer refused (not a sell offer)",
          any("SELL" in x for x in C.check_nft_offer(no_owner, pol_on)))
    bad_owner = bid_tx(owner="notanaddress")
    check("bid with bad Owner refused",
          any("Owner" in x for x in C.check_nft_offer(bad_owner, pol_on)))
    no_exp_bid = bid_tx()
    del no_exp_bid["Expiration"]
    check("bid without Expiration denied",
          any("Expiration" in d for d in nft_denials(
              no_exp_bid, "nft-bid")[0]))

    # envelope orientation: nft-list/nft-bid/nft-buy labels are binding
    def prop_for(action, account=ACCT):
        return {"account": account, "network": "testnet",
                "proposal_hash": "h", "created_at": int(time.time()),
                "action": action, "policy_version": C.POLICY_VERSION,
                "tx": {}}

    check("nft-bid action matches a buy offer",
          invariants_raise(prop_for("nft-bid"), bid_tx()) is None)
    check("nft-list action on a buy offer rejected",
          invariants_raise(prop_for("nft-list"), bid_tx()) is not None)
    check("nft-bid action on a sell offer rejected",
          invariants_raise(prop_for("nft-bid"), list_tx()) is not None)
    check("nft-buy action matches NFTokenAcceptOffer",
          invariants_raise(prop_for("nft-buy", DEST), accept_tx()) is None)
    check("nft-buy action on OfferCreate rejected",
          invariants_raise(
              prop_for("nft-buy"),
              {"TransactionType": "OfferCreate", "Account": ACCT}) is not None)

    # spend accounting: bids lock XRP, sell offers don't
    spends = C.tx_spends(bid_tx(amount="1000000"))
    check("bid locks its XRP in spends",
          spends["XRP"] == Decimal("1") + Decimal(drops_to_xrp("12")))
    spends = C.tx_spends(list_tx())
    check("sell offer spends fee only",
          spends["XRP"] == Decimal(drops_to_xrp("12")))

    # signer-level: full check_policy on the accept with toggle off
    # (client never touched — the toggle denies first)
    d_all, _sp = S.check_policy({"network": "testnet"}, accept_tx(),
                                C.load_policy(), None, C.SpentTracker())
    check("signer denies accept when buy side disabled",
          any("allow_buy_offers" in x for x in d_all))

    # ceremony text
    blines = "\n".join(C.describe_tx(bid_tx(), "nft-bid"))
    check("bid ceremony marks it a BUY offer", "BUY" in blines)
    alines = "\n".join(C.describe_tx(accept_tx(), "nft-buy"))
    check("accept ceremony shows the offer index", OFFER_IDX in alines)

    # --- 16. P1-4: stage digest binds content; pin uploads the hashed bytes ---
    # No network: the pinner's transport is faked, propose() is stubbed.
    import hashlib as _hl
    tmedia = Path(tempfile.mkdtemp(prefix="xrpl-p14-media-"))
    C.STAGE_DIR = tmp / "stage"
    T.xrpl_pin = P  # the test-loaded pinner module
    real_pmd = P.protected_media_dir
    P.protected_media_dir = lambda: str(tmedia)
    real_propose = T.propose
    proposed = {}

    def fake_propose(tx, client, cfg, action, summary_lines):
        proposed["summary"] = "\n".join(summary_lines)
        proposed["action"] = action
        return "deadbeef" * 8

    T.propose = fake_propose
    real_pin_data = P.pin_data
    real_pin_json = P.pin_json
    pinned = {}

    def fake_pin_data(data, filename):
        pinned["bytes"] = bytes(data)  # capture exactly what is uploaded
        pinned["filename"] = filename
        return "bafyimgcid"

    def fake_pin_json(obj, name="metadata.json"):
        pinned["meta"] = dict(obj)
        return "bafymetacid"

    P.pin_data = fake_pin_data
    P.pin_json = fake_pin_json
    PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    art = tmedia / "art.png"
    art.write_bytes(PNG)
    real_art = os.path.realpath(str(art))
    real_media = os.path.realpath(str(tmedia))
    ncfg = {"address": ACCT, "network": "testnet"}

    def expect_exit(fn, *a, **k):
        try:
            fn(*a, **k)
        except SystemExit as e:
            return str(e)
        return None

    rec = T.stage_artwork(str(art), "Cool Art", "A test piece", 1000, 0,
                          account=ACCT, network="testnet")
    dg = rec.get("stage_digest")
    check("stage record carries a 64-hex stage digest",
          isinstance(dg, str) and len(dg) == 64
          and all(c in "0123456789abcdef" for c in dg))
    expect = T._compute_stage_digest(
        _hl.sha256(PNG).hexdigest(), "Cool Art", "A test piece", 1000, 0,
        T.NFT_MINT_FLAGS, ACCT, "testnet", real_art, real_media)
    check("stage digest matches independent recomputation", dg == expect)
    sid = rec["stage_id"]
    stage_file = C.STAGE_DIR / f"{sid}.json"

    # happy path: pin uploads the EXACT staged bytes, ceremony shows digest
    h = T.pin_and_propose_stage(sid, ncfg, None, approved_digest=dg)
    check("pin succeeds on an unmodified stage", h == "deadbeef" * 8)
    check("pin uploads the exact bytes that were hashed",
          pinned.get("bytes") == PNG)
    check("approval ceremony carries the full stage digest",
          dg in proposed.get("summary", ""))

    # tamper 1: edited metadata in the stage record
    rec2 = dict(rec)
    rec2["royalty_bps"] = 5000
    stage_file.write_text(json.dumps(rec2))
    msg = expect_exit(T.pin_and_propose_stage, sid, ncfg, None, approved_digest=dg)
    check("pin refuses edited stage metadata before Pinata",
          msg is not None and "stage digest does not match" in msg
          and "NOT contacted" in msg)

    # tamper 2: swapped artwork file (still a valid PNG, different bytes)
    stage_file.write_text(json.dumps(rec))  # restore
    art.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\xff" * 100)
    msg = expect_exit(T.pin_and_propose_stage, sid, ncfg, None, approved_digest=dg)
    check("pin refuses a swapped artwork file",
          msg is not None and "changed since staging" in msg)
    art.write_bytes(PNG)  # restore

    # tamper 3: changed source path in the stage record (identical bytes,
    # so the file-hash check passes and the DIGEST must catch the path)
    other = tmedia / "other.png"
    other.write_bytes(PNG)
    rec3 = dict(rec)
    rec3["source_path"] = os.path.realpath(str(other))
    stage_file.write_text(json.dumps(rec3))
    msg = expect_exit(T.pin_and_propose_stage, sid, ncfg, None, approved_digest=dg)
    check("pin refuses a changed source path",
          msg is not None and "stage digest does not match" in msg)

    # tamper 4: a different minter account at pin time
    stage_file.write_text(json.dumps(rec))  # restore
    msg = expect_exit(T.pin_and_propose_stage, sid,
                      {"address": DEST, "network": "testnet"}, None, approved_digest=dg)
    check("pin refuses a different minter account",
          msg is not None and "stage digest does not match" in msg)

    # tamper 5: stage record points outside the protected media dir
    outside = Path(tempfile.mkdtemp(prefix="xrpl-p14-out-"))
    oart = outside / "evil.png"
    oart.write_bytes(PNG)
    rec5 = dict(rec)
    rec5["source_path"] = str(oart)
    stage_file.write_text(json.dumps(rec5))
    msg = expect_exit(T.pin_and_propose_stage, sid, ncfg, None, approved_digest=dg)
    check("pin refuses artwork outside the protected media dir",
          msg is not None and "outside the NFT media directory" in msg)

    # staging itself refuses files outside the protected media dir
    msg = expect_exit(T.stage_artwork, str(oart), "Evil", "", 1000, 0,
                      ACCT, "testnet")
    check("stage refuses files outside the protected media dir",
          msg is not None and "outside the NFT media directory" in msg)

    # old (pre-digest) stage records are rejected
    rec6 = dict(rec)
    rec6["format"] = "nft-stage/1"
    stage_file.write_text(json.dumps(rec6))
    msg = expect_exit(T.pin_and_propose_stage, sid, ncfg, None, approved_digest=dg)
    check("pre-digest stage records are rejected",
          msg is not None and "unsupported format" in msg)

    # restore the pinner module
    P.protected_media_dir = real_pmd
    T.propose = real_propose
    P.pin_data = real_pin_data
    P.pin_json = real_pin_json

n_fail = sum(1 for _, ok in PASS if not ok)
print(f"\n{len(PASS) - n_fail}/{len(PASS)} passed")
sys.exit(1 if n_fail else 0)
