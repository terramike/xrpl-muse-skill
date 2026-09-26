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

## Safety model (v0.7)

The skill is split into a proposer (`xrpl-trade`, never sees the seed) and a
policy-gated signer (`xrpl-sign`, the only program that touches the seed).
Every write is a hash-bound proposal envelope (v4): the approval hash covers
the network, account, action, creation time, policy version, bound signing
profile, policy SHA-256 digest, and the canonical XRPL binary of the complete
transaction. The signer re-verifies the envelope,
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

### Safety model additions (v0.6.0, unreleased)

- **Fail-closed spend state.** A corrupt `state.json` aborts signing with
  printed recovery steps — it is never treated as an empty ledger (which
  would silently reset rolling limits). Unbound spend/mint reservations
  are always released; only bound ones survive for reconciliation.
- **Validated-ledger NFT reads.** Offer entries and ownership checks pin
  to one validated ledger index and refuse unvalidated data.
- **Terminal sanitization.** All human-supplied or ledger-supplied text
  shown in ceremonies (mint descriptions, decoded URIs, favorites notes)
  is neutralized for ANSI/OSC escape sequences, control characters, and
  bidi overrides.
- **Full-hash approval.** `--approve` requires the exact 64-character
  proposal hash; prefixes are read-only conveniences, never approval.
- **Pinata stage vs pin-and-propose.** `nft-stage` validates artwork with
  zero network calls; `nft-pin-and-propose` re-validates the staged hash,
  pins, and proposes as one approved action. The pinner only ever sees
  the validated file and the exact reviewed metadata. `PINATA_JWT` is
  read from the environment at pin time only — never stored, logged, or
  written into proposals.
- **Issuer vs seller.** The buy ceremony shows the on-ledger **issuer**
  (minter) on its own line, distinct from the seller (current owner).
  The human verifies the issuer is the artist they expect.
- **Strict policy schema.** `load_policy()` rejects unknown keys, wrong
  types, out-of-range values, bad addresses, unsupported networks/tx
  types, and zero/negative TTLs with one fail-closed error. The buy side
  is double opt-in: `NFTokenAcceptOffer` is absent from the default
  `allowed_tx_types` *and* `nft.allow_buy_offers` defaults to false.

### Giveaway paths (v0.6.0 item 9)

The giveaway code (new after the v0.5.1 audit) gets the same treatment:

- The donation wallet's spend state (`giveaway_state.json`) uses the
  same `SpentTracker` — corrupt state fails closed with recovery steps,
  never as an empty ledger.
- NFT gift ownership checks pin to the validated ledger and refuse
  unvalidated data, like the buy-side reads.
- The `announce` draft sanitizes the human-supplied prize text for the
  terminal.
- Giveaway proposals sign through the same full-hash `--approve` gate,
  under the narrow giveaway policy (which passes the strict schema —
  `giveaway` and `allow_any_payment_destination` are known, typed keys).
- Seed handling: vault injection of `XRPL_GIVEAWAY_SEED` at signing time
  is the preferred path. Local storage in `giveaway.json` is a deliberate
  fallback — getpass entry (never echoed), verified to derive the
  donation wallet before anything is stored, atomic `0600` write — and
  `check_protected_files` covers it plus the giveaway policy in giveaway
  mode. The seed never appears in output, logs, proposals, or chat.

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

A same-user local agent does **not** satisfy condition 3, even with `0600`
files: a same-UID process can read the signer's environment variables and
rewrite its policy, state, and even the signer program itself. `0600`
protects against *other users*, not against the agent running as you.
Same-user installs are therefore testnet-only by policy — `install.sh`
says so on every run.

Without those platform guarantees, v0.5 is a hardened testnet tool. Do not
describe it as generically mainnet-safe.

### What actually protects the signer (v0.6.0 item 10 — verified)

`check_protected_files()` runs at the start of every `xrpl-sign`
invocation, before proposal verification and signing. Verified behavior
(covered by regression tests):

- Every *existing* protected file — `policy.json`, `approved.json`,
  `favorites.json`, `state.json`, `state.lock`, `audit.log` (plus
  `giveaway_policy.json` and `giveaway.json` in giveaway mode) — must be
  owned by the current UID and have no group/world permission bits, or
  the signer refuses to run.
- Absent files are skipped: only an absent state file means empty state.
- On non-POSIX systems the check silently does nothing — the deployment
  must protect those files another way.

Honest limits, verified the same way:

- **Nothing in the code protects `bin/xrpl-sign` itself.** The check
  covers data files, not the program. A process running as you can
  rewrite the signer, and no check will notice. Protecting the binary
  is a deployment job (read-only install owned by another UID, signed
  releases — see below).
- **`0600` does not stop a same-UID process.** Demonstrated
  empirically: a file chmod'd `0600` can still be rewritten by the same
  user with no privilege escalation. The permission check is a
  multi-user-OS boundary (it keeps *other* users out); it is not a
  boundary between you and software running as you.
- **The audit log is append-only, not tamper-evident.** It is `0600`
  JSONL, but it is not hash-chained — a same-UID process can rewrite or
  truncate it undetectably. Treat it as an operational record, not as
  proof against a compromised account.
- **The proposals directory is deliberately unprotected.** Proposals are
  treated as hostile input and fully verified (hash-bound envelope,
  TTL, policy checks) on every signing run.

Net: on a shared POSIX machine the check is real protection against
other users. Against anything running as your UID — including the
agent itself — the protection is the vault-held seed, the
propose→approve→sign ceremony with genuine per-transaction human
approval, and a deployment where the agent cannot rewrite the signer
or its policy. Without that deployment, same-user installs stay
testnet-only.

## Operator rules (all versions)

- Every trade, transfer, trustline, cancellation, NFT mint, NFT listing,
  NFT buy, and NFT bid requires the operator's explicit approval of the
  exact action, amount, price, destination, network, and proposal hash.
  Minting, listing, buying, and bidding are separate writes — approve
  each one.
- NFTs are pinned under the operator's **own** Pinata account, in two
  steps: `nft-stage` (offline review) then `nft-pin-and-propose` (the
  approved action that pins). `PINATA_JWT` is injected for the single
  pin operation only — never exported into a shell, never written to a
  file, never in the repo, proposals, logs, or chat. The publisher hosts
  no one's media. Pinning is an external write; it happens *inside* the
  approved action, not before it.
- **Counterfeit risk:** anyone can mint an NFT with the same artwork or a
  similar name. Before buying, verify the **issuer address** (the minter)
  is the artist you expect — the `nft-buy` ceremony shows the on-ledger
  seller, issuer, token URI, and taxon for exactly this reason. The skill
  reports on-ledger facts; it does not authenticate art.
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
- **Wallet creation:** `wallet create` generates the seed locally and stores
  it in `~/.xrpl/config.json` (0600, atomic) without ever displaying it —
  the seed must not appear in stdout, stderr, logs, proposals, or chat.
  `wallet backup` is the single deliberate display, for write-down. If a
  seed ever touches chat or a log, the wallet is burned: generate a new one,
  don't try to salvage it. Onboarding offers generation with default **no**.
  Honest boundary: on a machine where the agent runs, "never displayed"
  means transcript/output hygiene plus 0600 — true operator/agent
  separation needs the privileged-signer profile from "The platform
  boundary" above.

## Release & commit hygiene

- Security-relevant changes ship with honest commit messages that say
  what the change does and why — no cutesy titles on substantive diffs.
- Release tags are signed (`git tag -s`). A release is cut only when the
  full deterministic suite is green, every planned security item has
  landed with its regression tests, and the operator has approved the
  release explicitly. No partial security releases.
- Public history is never rewritten. If a published commit message
  misdescribed its diff, the correction goes in the next honest commit
  and the release notes — not in a force-push.
