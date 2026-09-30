#!/usr/bin/env python3
"""Tests for the onboarding wizard spec (references/onboarding-wizard.md).

The wizard runs in chat — these tests validate the spec's internal
consistency: every tracked step is covered, every question has
yes/no branches, the state schema parses, and the hard rules are stated.
No network needed.
"""
import json
import os
import re
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPEC = os.path.join(REPO, "references", "onboarding-wizard.md")
SKILL = os.path.join(REPO, "SKILL.md")

STEP_IDS = [
    "install", "setup", "init_policy", "profile", "first_read",
    "onchain", "watch_offers", "nft_minting", "nft_buying", "xrplto_key",
    "fiat_onramp", "autopilot", "autonomous", "giveaway",
]

QUESTION_IDS = ["onchain", "watch_offers", "nft_minting", "nft_buying",
                "xrplto_key", "fiat_onramp"]


def read_spec():
    with open(SPEC, encoding="utf-8") as fh:
        return fh.read()


class TestWizardSpec(unittest.TestCase):
    def test_spec_exists(self):
        self.assertTrue(os.path.isfile(SPEC), "onboarding-wizard.md missing")

    def test_state_schema_is_valid_json(self):
        text = read_spec()
        m = re.search(r"```json\n(.*?)```", text, re.DOTALL)
        self.assertIsNotNone(m, "no ```json state schema block found")
        schema = json.loads(m.group(1))
        self.assertEqual(schema["schema_version"], 1)
        steps = schema["steps"]
        for sid in STEP_IDS:
            self.assertIn(sid, steps, f"step {sid!r} missing from schema")
        for sid, state in steps.items():
            self.assertIn(state, ("pending", "done", "skipped"),
                          f"step {sid!r} has invalid state {state!r}")

    def test_every_step_id_covered_in_body(self):
        # step ids may appear as their CLI command form (init-policy)
        # or their display name (First read) rather than the raw id
        markers = {
            "install": ["install"],
            "setup": ["setup"],
            "init_policy": ["init_policy", "init-policy"],
            "profile": ["profile"],
            "first_read": ["first_read", "First read"],
            "onchain": ["onchain"],
            "watch_offers": ["watch_offers", "watch add"],
            "nft_minting": ["nft_minting"],
            "nft_buying": ["nft_buying", "nft-buy"],
            "xrplto_key": ["xrplto_key"],
            "fiat_onramp": ["fiat_onramp"],
            "autopilot": ["autopilot"],
            "autonomous": ["autonomous"],
            "giveaway": ["giveaway"],
        }
        text = read_spec()
        body = re.sub(r"```json\n.*?```", "", text, flags=re.DOTALL)
        for sid in STEP_IDS:
            found = any(m in body for m in markers[sid])
            self.assertTrue(found, f"step {sid!r} never discussed in spec")

    def test_each_question_has_yes_and_no_branches(self):
        text = read_spec()
        for qid in QUESTION_IDS:
            # find the question block: from its step id mention to the next Q header
            idx = text.find(qid)
            self.assertGreater(idx, -1)
            block = text[idx:idx + 4500]
            self.assertRegex(block, r"\*\*Yes\*\*",
                             f"question {qid!r} has no documented Yes branch")
            self.assertRegex(block, r"\*\*(No|Skip)\*\*",
                             f"question {qid!r} has no documented No/Skip branch")

    def test_advanced_gate_covers_three_features(self):
        text = read_spec()
        for sid in ("autopilot", "autonomous", "giveaway"):
            self.assertIn(sid, text, f"advanced feature {sid!r} not in spec")

    def test_important_step_marked(self):
        text = read_spec()
        onchain = text[text.find("**Q1"):text.find("**Q1") + 800]
        self.assertIn("IMPORTANT", onchain,
                      "Q1 (on-chain) must be marked IMPORTANT")

    def test_bot_signing_wording(self):
        text = read_spec()
        self.assertIn("human in the loop", text.lower(),
                      "wizard must frame autopilot as human-in-the-loop "
                      "bot signing, not just 'autopilot'")

    def test_watch_question_is_read_only(self):
        text = read_spec()
        q2 = text[text.find("**Q2"):text.find("**Q2") + 1200]
        self.assertRegex(q2, r"(?i)read-only",
                         "Q2 (offer watch) must be marked read-only")
        self.assertRegex(q2, r"(?i)no\s+keys",
                         "Q2 (offer watch) must say no keys needed")
        self.assertIn("watch add", q2,
                      "Q2 must show the watch add command")

    def test_q1_covers_pairs_and_allowlist(self):
        text = read_spec()
        q1 = text[text.find("**Q1"):text.find("**Q2")]
        self.assertIn("approved.json", q1,
                      "Q1 yes-path must cover trade-pair setup")
        self.assertIn("allowlist", q1.lower(),
                      "Q1 yes-path must cover the destination allowlist")

    def test_buy_nfts_question_exists(self):
        text = read_spec()
        self.assertIn("**Q4", text)
        q4 = text[text.find("**Q4"):text.find("**Q4") + 1500]
        self.assertIn("allow_buy_offers", q4,
                      "Q4 must cover the allow_buy_offers policy flip")
        self.assertIn("nft-bid", q4, "Q4 must cover bidding")

    def test_phase0_power_reads(self):
        text = read_spec()
        phase0 = text[text.find("## Phase 0"):text.find("## Phase 1")]
        for cmd in ["tx-explain", "whale-watch", "token-safety",
                    "top-collections", "xrpresso", "trusted-links",
                    "validators", "amendments"]:
            self.assertIn(cmd, phase0,
                          f"Phase 0 try-list missing: {cmd}")

    def test_nice_to_have_marked(self):
        text = read_spec()
        self.assertIn("nice-to-have", text,
                      "xrpl.to key question must be marked nice-to-have")

    def test_hard_rules_present(self):
        text = read_spec()
        rules = text[text.find("## Hard rules"):].lower()
        for rule in ["never ask for a seed", "buttons first", "no nagging",
                     "exact diffs", "testnet before mainnet"]:
            self.assertIn(rule, rules, f"hard rule missing: {rule!r}")

    def test_no_seed_collection_path(self):
        text = read_spec()
        self.assertRegex(text, r"never\s+in chat",
                         "spec must state credentials are never in chat")

    def test_skill_md_references_wizard(self):
        with open(SKILL, encoding="utf-8") as fh:
            skill = fh.read()
        self.assertIn("references/onboarding-wizard.md", skill)
        self.assertIn("Finish your setup", skill)
        self.assertIn("onboarding.json", skill)


if __name__ == "__main__":
    unittest.main()
