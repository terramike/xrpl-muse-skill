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

## Safety model (v0.3)

The skill is split into a proposer (`xrpl-trade`, never sees the seed) and a
policy-gated signer (`xrpl-sign`, the only program that touches the seed).
Every write is a hash-bound proposal envelope: the approval hash covers the
network, account, action, creation time, policy version, and the canonical
XRPL binary of the complete transaction. The signer re-verifies the envelope,
derives the summary from the transaction itself (nothing stored is trusted),
and enforces:

- transaction-type allowlist (`OfferCreate`, `OfferCancel`, `TrustSet`,
  `Payment`) with strict per-type field schemas,
- exact-pair enforcement from the approved-pairs allowlist,
- per-asset per-transaction and rolling-24h spend limits (unconfigured
  assets are blocked),
- destination `(address, tag)` allowlisting plus `RequireDestTag`
  enforcement,
- offer expiry and book-deviation limits,
- network lock (testnet by default),
- sign → persist (hash + `LastLedgerSequence`) → submit → validated result.

## The platform boundary — read before mainnet

`--approve` is an **assertion**, not evidence of human approval. v0.3 is
mainnet-ready **only** when all of these hold:

1. Muse requires real user confirmation for each signing use. A typed
   command in a chat transcript is not consent by itself.
2. The vault releases `XRPL_SEED` to the signer only on that genuine
   confirmation. The seed must never be a hand-exported shell variable in a
   shared environment, and the shipped signer reads it from nowhere else
   (no config-file fallback).
3. The signer and the protected policy file sit behind a vault, separate OS
   identity, or privileged signing service that the agent cannot rewrite —
   the agent must not be able to alter signing policy or activate signing
   merely by passing `--approve`.

Without those platform guarantees, v0.3 is a hardened testnet tool. Do not
describe it as generically mainnet-safe.

## Operator rules (all versions)

- Every trade, transfer, trustline, or cancellation requires the operator's
  explicit approval of the exact action, amount, price, destination, network,
  and proposal hash.
- Always inspect the proposal ceremony before approving. `tesSUCCESS` alone
  does not prove trade direction — check `TakerPays`/`TakerGets` orientation.
- Trade only from a dedicated limited-funds wallet. Never use a life-savings
  wallet with an agent skill.
- Old-format (`xrpl-proposal/2`) proposals are rejected by the v0.3 signer;
  rebuild them — never hand-edit a proposal file.
