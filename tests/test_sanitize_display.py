#!/usr/bin/env python3
"""v0.14.1 regression tests: approval-display sanitization (audit finding #2).

Every untrusted field shown during the signing ceremony passes through
safe_terminal_text (or the equivalent local _text in xrpresso): hostile
bytes (ANSI escapes, OSC clipboard sequences, C0/C1 controls, bidi
overrides, line/paragraph separators, DEL) render as VISIBLE escapes —
they can neither act on the terminal nor hide invisibly. Legit Unicode
(emoji, CJK, accents) passes through untouched. Truncation ends with an
ellipsis inside the requested limit.

No network. Run: python3 -m unittest tests.test_sanitize_display
"""
import importlib.util
import sys
import unittest
from pathlib import Path

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


C = _load(BIN / "xrpl_common.py", "xrpl_common_sanitize")
X = _load(BIN / "xrpl_xrpresso.py", "xrpl_xrpresso_sanitize")


class SanitizeDisplayTest(unittest.TestCase):
    def test_ansi_escape_visible(self):
        out = C.safe_terminal_text("\x1b[31mRED")
        self.assertNotIn("\x1b", out)
        self.assertIn("RED", out)
        self.assertIn("\\x1b", out)

    def test_osc52_clipboard_sequence_neutered(self):
        # OSC-52 can overwrite the operator's clipboard — must not survive.
        evil = "\x1b]52;c;ZmFrZQ==\x07"
        out = C.safe_terminal_text(evil)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_newline_tab_visible(self):
        out = C.safe_terminal_text("line1\nline2\ttab")
        self.assertEqual(out, "line1\\nline2\\ttab")

    def test_bidi_override_visible(self):
        # U+202E right-to-left override can visually reorder text.
        out = C.safe_terminal_text("abc\u202eDEF")
        self.assertNotIn("\u202e", out)
        self.assertIn("abc", out)
        self.assertIn("DEF", out)

    def test_c1_and_del_visible(self):
        out = C.safe_terminal_text("\x85\x9b\x7f")
        self.assertNotIn("\x85", out)
        self.assertNotIn("\x9b", out)
        self.assertNotIn("\x7f", out)

    def test_unicode_separators_visible(self):
        out = C.safe_terminal_text("a\u2028b\u2029c")
        self.assertNotIn("\u2028", out)
        self.assertNotIn("\u2029", out)
        self.assertIn("a", out)
        self.assertIn("c", out)

    def test_legit_unicode_survives(self):
        txt = "🎨 日本語 café naïve → 100%"
        self.assertEqual(C.safe_terminal_text(txt), txt)

    def test_truncation_ends_with_ellipsis_inside_limit(self):
        out = C.safe_terminal_text("x" * 200, max_len=20)
        self.assertTrue(len(out) <= 20)
        self.assertTrue(out.endswith("…"))

    def test_none_and_nonstring(self):
        self.assertEqual(C.safe_terminal_text(None), "")
        self.assertEqual(C.safe_terminal_text(123), "123")

    def test_decode_nft_uri_sanitizes(self):
        # attacker-controlled on-ledger URI, hex-encoded
        evil = "\x1b]0;pwned\x07".encode().hex()
        out = C.decode_nft_uri(evil)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)

    def test_decode_nft_uri_bad_hex(self):
        self.assertEqual(C.decode_nft_uri("zz"), "<uri is not valid hex>")

    def test_decode_nft_uri_respects_limit(self):
        out = C.decode_nft_uri("ab" * 200, limit=20)
        self.assertTrue(len(out) <= 20)

    def test_xrpresso_text_same_contract(self):
        # _text is the local equivalent: same escaping, 300-char cap.
        evil = "ok\x1b[31m\n\u202e" + "y" * 400
        out = X._text(evil)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\n", out)
        self.assertNotIn("\u202e", out)
        self.assertIn("ok", out)
        self.assertTrue(len(out) <= 300)
        self.assertTrue(out.endswith("..."))
        self.assertEqual(X._text(None), "")
        self.assertEqual(X._text("🎨 ok"), "🎨 ok")


if __name__ == "__main__":
    unittest.main()
