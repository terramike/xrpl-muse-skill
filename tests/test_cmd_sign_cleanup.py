#!/usr/bin/env python3
"""v0.14.1 regression tests: cmd_sign() reservation cleanup.

Direct entry-point tests for the headline v0.6.0 regression: if signing
aborts AFTER the atomic budget reservations are taken, both the spend
reservation AND the mint reservation must be released — otherwise a
phantom pending hold burns the operator's daily budget with no tx hash
that sweep_pending could ever resolve.

Covered: sign_tx raising, signed.get_hash() raising (incl.
KeyboardInterrupt), and load_seed exiting on a missing/unreadable seed.

No network (client, ledger, and wallet are faked). Run:
python3 -m unittest tests.test_cmd_sign_cleanup
"""
import importlib.util
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from decimal import Decimal
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

BIN = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN))


def _load(path, name):
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    loader.exec_module(mod)
    return mod


C = _load(BIN / "xrpl_common.py", "xrpl_common")
S = _load(BIN / "xrpl-sign", "xrpl_sign_cmdsign")

ACCOUNT = "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB"
DEST = "rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB"
FULL = "c" * 64
NOW = int(time.time())


def payment_tx():
    return {"TransactionType": "Payment", "Account": ACCOUNT,
            "Destination": DEST, "Amount": "1000000", "Fee": "12",
            "Sequence": 1, "LastLedgerSequence": NOW + 100}


def mint_tx():
    return {"TransactionType": "NFTokenMint", "Account": ACCOUNT,
            "NFTokenTaxon": 0, "Flags": 8, "Fee": "12",
            "Sequence": 1, "LastLedgerSequence": NOW + 100}


def test_policy():
    return {"spend_limits": {"XRP": {"per_tx": "1000000",
                                    "per_day": "1000000"},
                            "NFT_MINT": {"per_tx": "100",
                                         "per_day": "100"}},
            "proposal_ttl_seconds": 86400,
            "nft": {"max_mints_per_day": 10}}


class FakeWallet:
    classic_address = ACCOUNT

    @staticmethod
    def from_seed(seed):
        return FakeWallet()


class CmdSignCleanupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._saved_c = {}
        for k in ("STATE_PATH", "STATE_LOCK_PATH", "AUDIT_PATH"):
            self._saved_c[k] = getattr(C, k)
            setattr(C, k, self.tmp / k.lower().replace("_path", ""))
        self._saved_s = {}
        self.tx = payment_tx()
        self.prop = {"proposal_hash": FULL, "network": "testnet",
                     "action": "test", "account": ACCOUNT,
                     "created_at": NOW}

        def patch_c(name, fn):
            self._saved_c["C." + name] = getattr(C, name)
            setattr(C, name, fn)

        def patch_s(name, fn):
            self._saved_s["S." + name] = getattr(S, name)
            setattr(S, name, fn)

        self.patch_c, self.patch_s = patch_c, patch_s
        patch_c("is_read_only", lambda: False)
        patch_c("load_proposal_exact", lambda h: (self.prop, Path("p.json")))
        patch_c("verify_proposal", lambda prop, path: self.tx)
        patch_c("verify_envelope_invariants", lambda prop, tx: None)
        patch_c("require_full_hash_for_approve", lambda h, prop: None)
        patch_c("check_protected_files", lambda extra=(): None)
        patch_c("make_client", lambda net: object())
        patch_c("check_signer_authorization",
                lambda client, acct, derived: None)
        patch_c("check_ledger_key_authorization",
                lambda client, acct, derived: None)
        patch_s("resolve_signing_context",
                lambda args, prop: (test_policy(), ("env", "XRPL_SEED"),
                                    False, "test"))
        patch_s("check_policy",
                lambda prop, tx, policy, client, tracker:
                ([], {"XRP": Decimal("0.00001")}))
        patch_s("Wallet", FakeWallet)

    def tearDown(self):
        for k, v in self._saved_c.items():
            if k.startswith("C."):
                setattr(C, k[2:], v)
            else:
                setattr(C, k, v)
        for k, v in self._saved_s.items():
            setattr(S, k[2:], v)

    def pending_entries(self):
        tr = C.SpentTracker()
        st = tr._load()
        return [e for e in st["entries"] if e.get("status") == "pending"]

    def run_sign(self):
        args = SimpleNamespace(approve=True, hash=FULL)
        buf = StringIO()
        with redirect_stdout(buf):
            S.cmd_sign(args)

    def test_seed_missing_releases_spend_reservation(self):
        self.patch_s("load_seed", lambda src: (_ for _ in ()).throw(
            SystemExit("No seed: the vault did not inject XRPL_SEED")))
        with self.assertRaises(SystemExit):
            self.run_sign()
        self.assertEqual(self.pending_entries(), [])

    def test_sign_tx_raises_releases_both_reservations(self):
        self.tx = mint_tx()  # exercises the mint reservation too
        self.patch_s("load_seed", lambda src: "s" * 29)
        def boom(tx_obj, wallet):
            raise RuntimeError("HSM exploded")
        self.patch_s("sign_tx", boom)
        with self.assertRaises(RuntimeError):
            self.run_sign()
        self.assertEqual(self.pending_entries(), [])

    def test_get_hash_keyboard_interrupt_releases_both(self):
        self.tx = mint_tx()
        self.patch_s("load_seed", lambda src: "s" * 29)

        class Signed:
            def get_hash(self):
                raise KeyboardInterrupt()

        self.patch_s("sign_tx", lambda tx_obj, wallet: Signed())
        with self.assertRaises(KeyboardInterrupt):
            self.run_sign()
        self.assertEqual(self.pending_entries(), [])

    def test_invalid_seed_releases_both_reservations(self):
        self.tx = mint_tx()

        class BadWallet:
            @staticmethod
            def from_seed(seed):
                raise ValueError("bad seed")

        self.patch_s("load_seed", lambda src: "bogus")
        self.patch_s("Wallet", BadWallet)
        with self.assertRaises(SystemExit):
            self.run_sign()
        self.assertEqual(self.pending_entries(), [])


if __name__ == "__main__":
    unittest.main()
