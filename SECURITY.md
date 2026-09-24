# Security Policy

## Reporting a vulnerability

Open a GitHub issue titled `[security]` or contact the maintainer through the
profile email on https://github.com/terramike. Do not post exploit details
publicly before a fix is available.

## Known issue — do not trade on versions before c3273e59

Commit `ed8fa202` ("XRPL trading skill for Muse: CLI + docs + installer")
shipped with `buy` and `sell` constructing **inverted offers**: `buy` placed a
sell offer and `sell` placed a buy offer. Trade direction was corrected in
commit `c3273e59` ("fix: buy/sell had TakerPays/TakerGets inverted").

**If you cloned, forked, or downloaded this repository at commit `ed8fa202`,
do not use it for trading.** Update to `c3273e59` or later and re-verify with
`--dry-run` before submitting anything.

## Safety model (v0.1.x)

This skill is designed for a human-in-the-loop operator:

- Every trade, transfer, trustline, or cancellation requires the operator's
  explicit approval of the exact action, amount, price, and network.
- Always `--dry-run` first and inspect `TakerPays`/`TakerGets` orientation.
  `tesSUCCESS` alone does not prove trade direction.
- Trade only from a dedicated limited-funds wallet. Never use a life-savings
  wallet with an agent skill.

The v0.1.x CLI itself does not enforce these rules in code — they are the
operator's responsibility. The v0.2 release moves approval and policy
enforcement into a separate policy-gated signer so the protections hold no
matter which agent runs the skill.
