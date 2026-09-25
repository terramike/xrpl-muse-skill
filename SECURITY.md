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
do not use it for trading.** Update to `c3273e59` or later, rebuild the
proposal, review the signer's derived ceremony output, and confirm the
validated ledger result before relying on it.

## Safety model (v0.5)

The skill is split into a proposer (`xrpl-trade`, never sees the seed) and a
policy-gated signer (`xrpl-sign`, the only program that touches the seed).
Every write is a hash-bound proposal envelope: the approval hash covers the
network, account, action, creation time, policy version, and the canonical
XRPL binary of the complete transaction. The signer re-verifies the envelope,
derives the summary from the transaction itself (nothing stored is trusted),
and enforces:

- envelope invariants: envelope account == transaction `Account`, action
  matches transaction type (including `nft-mint`/`nft-list`/`nft-bid`/
  `nft-buy`), buy/sell orientation matches the actual `TakerPays`/
  `TakerGets` fields, and NFT offer orientation matches the label
  (`nft-list` ⇔ sell offer, `nft-bid` ⇔ buy offer with `Owner`);
  required fields (`Account`, `Fee`, `Sequence`, `LastLedgerSequence`)
  present; no signature material in unsigned proposals; no far-future
  `created_at`,

- transaction-type allowlist (v4 policy: the four trading types plus
  `NFTokenMint`, `NFTokenCreateOffer`, and `NFTokenAcceptOffer` when the
  operator enables them)
  with strict per-type field schemas (`NFTokenAcceptOffer` is direct-mode
  only: `NFTokenSellOffer` required; `NFTokenBuyOffer` and
  `NFTokenBrokerFee` are rejected),
- exact-pair enforcement from the approved-pairs allowlist,
- per-asset per-transaction and true rolling-24h spend limits (unconfigured
  assets are blocked; NaN/Infinity amounts are rejected before they can
  poison comparisons),
- destination `(address, tag)` allowlisting plus `RequireDestTag`
  enforcement (fail-closed on lookup errors),
- offer expiry within a bounded lifetime (`max_offer_lifetime_seconds`),
- book-deviation checks against a depth-weighted reference requiring both
  book sides, minimum depth, and a maximum spread,
- network lock (testnet by default),
- NFT gates (v0.5): royalty (`TransferFee`) capped at
  `nft.max_transfer_fee` and validated client-side from immutable bps,
  mint flags restricted to the allowlist, URI required and byte-capped,
  listing amounts XRP-only, sell offers only for listings (buy offers /
  bids carry `Owner` and are a separate policy-gated action), every
  listing carries a ledger `Expiration` bounded by
  `max_offer_lifetime_seconds`, and a rolling-24h mint count capped at
  `nft.max_mints_per_day`, reserved atomically like spend limits,
- NFT buy side (v0.5, opt-in via `nft.allow_buy_offers`, default off):
  `nft-buy` accepts **only** verified sell offers — the signer fetches
  the offer entry from the ledger and refuses buy offers, IOU-denominated
  amounts, and offers the seller no longer owns; the offer's XRP price is
  reserved through the normal per-tx / rolling-24h spend lifecycle. The
  signing ceremony re-verifies the offer at signing time and refuses if
  it changed. Bids (`nft-bid`) lock their XRP in the offer (counted toward
  spend limits like an `OfferCreate`'s `TakerGets`) and are capped per-bid
  by `nft.max_bid_xrp`. There is **no fungible order-book price check**
  for NFTs — each token is one-of-one; price sanity is the human's
  decision, and the skill never calls a token "authentic",
- ambiguity-safe reservations: a reserved spend stays reserved (never
  double-spent, never released early) until the validated ledger result
  proves what happened,
- protected files: the signer refuses to run if the policy, allowlist,
  state, lock, or audit files are not owner-only (this catches accidental
  exposure; it is not a substitute for the privileged boundary below).

## The platform boundary — read before mainnet

`--approve` is an **assertion**, not evidence of human approval. v0.5 is
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

Without those platform guarantees, v0.5 is a hardened testnet tool. Do not
describe it as generically mainnet-safe.

## Operator rules (all versions)

- Every trade, transfer, trustline, cancellation, NFT mint, NFT listing,
  NFT buy, and NFT bid requires the operator's explicit approval of the
  exact action, amount, price, destination, network, and proposal hash.
  Minting, listing, buying, and bidding are separate writes — approve
  each one.
- NFTs are pinned under the operator's **own** Pinata account. `PINATA_JWT`
  comes from the vault/environment only: it never goes into the repo,
  proposals, logs, or chat. The publisher hosts no one's media.
- **Counterfeit risk:** anyone can mint an NFT with the same artwork or a
  similar name. Before buying, verify the **seller address** against the
  minter you expect — the `nft-buy` ceremony shows the on-ledger seller,
  token URI, and taxon for exactly this reason. The skill reports
  on-ledger facts; it does not authenticate art.
- **Favorites track wallets, not identities.** A favorite is a name you
  chose for an r-address. If an artist changes wallets, the favorite
  goes stale — nothing re-verifies that the wallet still belongs to
  them. `xrp.cafe` links in `nft-new` are a convenience; the NFTokenID
  is the canonical identifier.
- Always inspect the proposal ceremony before approving. `tesSUCCESS` alone
  does not prove trade direction — check `TakerPays`/`TakerGets` orientation.
- Trade only from a dedicated limited-funds wallet. Never use a life-savings
  wallet with an agent skill.
- Old-format (`xrpl-proposal/2`) proposals are rejected by the v0.3 signer;
  rebuild them — never hand-edit a proposal file.
