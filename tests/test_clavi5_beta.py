"""Tests for bin/clavi5-beta: the Clavi5 multi-user beta client.

Behavior specs:
- init writes owner-only config and verifies the token.
- propose prints exact terms, calls request_propose, prints the sign URL.
  It NEVER submits and NEVER touches a seed.
- confirm calls request_confirm and reports the ledger status.
- status reports the killswitch state.
- No seeds are requested, revealed, or recorded anywhere.
"""
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

BIN = os.path.join(os.path.dirname(__file__), "..", "bin", "clavi5-beta")


def load_module():
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("clavi5_beta", BIN)
    spec = importlib.util.spec_from_loader("clavi5_beta", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class BetaConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg_path = os.path.join(self.tmp, "beta.json")

    def test_config_must_be_owner_only(self):
        mod = load_module()
        with patch.object(mod, "CONFIG_PATH", self.cfg_path):
            with open(self.cfg_path, "w") as f:
                json.dump({"approval_url": "https://x", "agent_token": "t"}, f)
            os.chmod(self.cfg_path, 0o644)
            with self.assertRaises(SystemExit):
                mod.load_config()

    def test_config_missing_keys_rejected(self):
        mod = load_module()
        with patch.object(mod, "CONFIG_PATH", self.cfg_path):
            with open(self.cfg_path, "w") as f:
                json.dump({"approval_url": "https://x"}, f)
            os.chmod(self.cfg_path, 0o600)
            with self.assertRaises(SystemExit):
                mod.load_config()

    def test_config_loads_when_valid(self):
        mod = load_module()
        with patch.object(mod, "CONFIG_PATH", self.cfg_path):
            with open(self.cfg_path, "w") as f:
                json.dump({"approval_url": "https://x", "agent_token": "t"}, f)
            os.chmod(self.cfg_path, 0o600)
            cfg = mod.load_config()
            self.assertEqual(cfg["agent_token"], "t")


class BetaProposeTest(unittest.TestCase):
    def test_propose_builds_correct_tx(self):
        mod = load_module()
        calls = {}

        def fake_api_post(url, token, body):
            calls["url"] = url
            calls["token"] = token
            calls["body"] = body
            return {"ok": True, "request_id": "req_test",
                    "sign_url": "https://x/sign?r=req_test"}

        def fake_xrpl_rpc(network, method, params):
            if method == "account_info":
                return {"account_data": {"Sequence": 100, "Balance": "10000000"}}
            if method == "ledger":
                return {"ledger_index": 200}
            raise AssertionError(method)

        with patch.object(mod, "api_post", fake_api_post), \
             patch.object(mod, "xrpl_rpc", fake_xrpl_rpc), \
             patch.object(mod, "load_config",
                          return_value={"approval_url": "https://a.example",
                                        "agent_token": "tok"}):
            mod.cmd_propose(["--to", "rDEST", "--amount-xrp", "1.5",
                             "--from-account", "rSRC", "--network", "testnet"])

        tx = calls["body"]["tx"]
        self.assertEqual(tx["account"], "rSRC")
        self.assertEqual(tx["destination"], "rDEST")
        self.assertEqual(tx["amount_drops"], "1500000")
        self.assertEqual(tx["sequence"], 100)
        self.assertEqual(tx["last_ledger_sequence"], 260)
        self.assertEqual(calls["body"]["network"], "TESTNET")
        self.assertTrue(calls["url"].endswith("/request_propose"))
        self.assertEqual(calls["token"], "tok")

    def test_propose_rejects_nonpositive_amount(self):
        mod = load_module()
        with patch.object(mod, "load_config",
                          return_value={"approval_url": "https://a.example",
                                        "agent_token": "tok"}):
            with self.assertRaises(SystemExit):
                mod.cmd_propose(["--to", "rDEST", "--amount-xrp", "0",
                                 "--from-account", "rSRC"])

    def test_propose_requires_from_account(self):
        mod = load_module()
        with patch.object(mod, "load_config",
                          return_value={"approval_url": "https://a.example",
                                        "agent_token": "tok"}):
            with self.assertRaises(SystemExit):
                mod.cmd_propose(["--to", "rDEST", "--amount-xrp", "1"])


class BetaConfirmTest(unittest.TestCase):
    def test_confirm_reports_status(self):
        mod = load_module()
        with patch.object(mod, "api_post",
                          return_value={"ok": True, "status": "confirmed"}), \
             patch.object(mod, "load_config",
                          return_value={"approval_url": "https://a.example",
                                        "agent_token": "tok"}):
            # Should not raise
            mod.cmd_confirm(["--request", "req_test"])

    def test_confirm_fails_closed(self):
        mod = load_module()
        with patch.object(mod, "api_post",
                          return_value={"ok": False, "error": "nope"}), \
             patch.object(mod, "load_config",
                          return_value={"approval_url": "https://a.example",
                                        "agent_token": "tok"}):
            with self.assertRaises(SystemExit):
                mod.cmd_confirm(["--request", "req_test"])


if __name__ == "__main__":
    unittest.main()
