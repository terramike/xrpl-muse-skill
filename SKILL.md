# xrpl-muse-skill

Trade the XRP Ledger from the terminal — any token pair, with a hard safety
boundary between proposing a trade and signing it.

## Architecture: propose → approve → sign (v0.7)

Two programs. The agent only ever runs the first.

1. **`xrpl-trade` — the proposer.** Builds transactions, autofills them against
   the live network, prints the full ceremony (account, network, assets with
   issuers, amounts, limit price, max spend, fee, sequence, expiry), and saves
   a **hash-bound proposal envelope**. It **never sees the seed** and **never
   submits**.
2. **`xrpl-sign` — the policy-gated signer.** The only program that touches the
   seed. On mainnet it reads the seed from a **named signing profile**
   (`~/.xrpl/profiles.json`, owner-only `0600`) that binds account + network +
   credential reference + policy digest + spend-state selection; the seed
   itself lives in the operator's vault (password manager) and is injected
   for the single signing operation. `xrpl-sign` verifies the proposal
   envelope, enforces the profile's policy, derives the summary from the
   transaction itself, and signs **only** when a human passes
   `--profile <name> --approve` for that exact hash.

### Signing profiles (v0.7)

A profile names the complete signing context so a proposal can't drift
across accounts, networks, policies, or wallets:

```json
{
  "schema_version": 1,
  "profiles": {
    "main": {
      "account": "r9e34ga9YxYHYoCe7UtWWpuLjp4iKs3gkB",
      "network": "mainnet",
      "credential_env": "XRPL_SEED",
      "policy_path": "/home/user/.xrpl/policy.json",
      "policy_sha256": "2d3aa5d2b830a43c…",
      "spend_state": "default"
    }
  }
}
```

- `xrpl-trade` records `profile` + `policy_sha256` in every mainnet proposal.
- `xrpl-sign --profile <name>` rejects proposals bound to another profile,
  a changed policy (digest mismatch → rebuild the proposal), or a different
  account/network — *before* touching the credential.
- One profile = one spend-state file, so the main wallet and the giveaway
  wallet can never share a budget.
- Manage with `xrpl-sign init-profiles` / `xrpl-sign sync-profile <name>`.

### Vault-only mainnet (v0.7)

Mainnet never keeps a seed on disk and never prints one to a terminal:

- `xrpl-trade wallet create --network mainnet` and `wallet backup --network
  mainnet` are refused (creation/backup of mainnet keys happens in the
  vault, outside this tool).
- The signer refuses to run on mainnet if legacy seeds remain in
  `~/.xrpl/config.json` or `~/.xrpl/giveaway.json` — migrate them first
  (`wallet forget-seed` removes a disk seed only after you type the address
  to confirm the vault backup).
- Testnet keeps the convenient local flow (`wallet create` prints the seed
  once; the faucet no longer does).

### Autopilot — at your own risk (opt-in local mainnet signing)

Two signing modes, clearly labeled:

- **Vault (default).** The key stays outside the agent's environment; the
  vault injects it for one signing operation after genuine human approval.
  External wallets (Xaman via its payload API, or a WalletConnect wallet
  like Joey/Bifrost once the bridge lands) keep the key in a separate
  wallet entirely — the user approves there.
- **Autopilot (explicit opt-in).** `xrpl-trade autopilot enable` stores the
  wallet's seed in `~/.xrpl/autopilot.json` (owner-only 0600) after the
  operator types `ENABLE AUTOPILOT` under a plain-language risk disclosure.
  Seed sourcing, in order: (1) if `~/.xrpl/config.json` holds a seed for the
  account (e.g. from `xrpl-trade wallet create`), it is adopted directly —
  no pasting; (2) otherwise the operator may generate a fresh dedicated
  autopilot wallet on the spot, with a one-time backup ceremony (the seed
  is displayed exactly once; the operator types `I HAVE WRITTEN IT DOWN`
  to confirm); (3) otherwise paste at a hidden prompt. The signer then
  uses the local seed — but **only** for the exact account it was enabled
  for, and **everything else is unchanged**: the proposal envelope, the
  policy checks (spend caps, pairs, tx types, fee caps, expiries), the
  audit log, and the human Submit/Cancel on the proposal hash in chat.

What Autopilot does and does not protect against — say this plainly:

- It bounds the agent's *mistakes*: policy + proposal + human confirmation
  still gate every transaction.
- It does **not** defend against the agent's *compromise*: this is a
  same-user install, so any process running as this user can read the seed
  file. A prompt-injected agent or a rooted machine exposes the seed.
- So: use a dedicated limited-funds wallet for Autopilot (not the vault),
  keep spend caps tight, and run `xrpl-trade autopilot disable` (which
  deletes the seed from disk after you type the address to confirm) the
  moment you stop needing it.

Never paste a seed into chat to enable this. The seed is entered at a
hidden terminal prompt, is never printed, logged, or echoed, and the audit
log records only `seed_source=autopilot` — never the seed.

### The envelope (what the hash binds)

A proposal is `format: xrpl-proposal/4` and the approval hash covers:

- `profile`, `policy_sha256`, `network`, `account`, `action`, `created_at`,
  `policy_version`
- the **canonical XRPL binary** of the complete transaction
  (`xrpl.core.binarycodec.encode`)

The signer re-verifies all of it and rejects anything tampered with —
including the envelope file itself. A proposal whose policy digest no
longer matches the profile's policy is rejected (rebuild it after reviewing
the policy change). Old-format proposals are rejected; rebuild them with the
current `xrpl-trade`.

### What the signer enforces

- **Envelope invariants**: envelope account == transaction `Account`,
  action matches transaction type, buy/sell orientation matches the actual
  `TakerPays`/`TakerGets` fields; `Account`, `Fee`, `Sequence`,
  `LastLedgerSequence` required; no `TxnSignature`/`SigningPubKey` in
  unsigned proposals; no far-future `created_at`.
- **Transaction-type allowlist**: `OfferCreate`, `OfferCancel`, `TrustSet`,
  `Payment` only. Anything else is rejected.
- **Strict per-type field schemas**: no `Paths`, `SendMax`, `DeliverMin`,
  `Memos`, partial-payment flags, or any other smuggled field.
- **Numeric sanity**: NaN/Infinity amounts, fees, and sequences are rejected
  before they can reach a limit comparison.
- **Derived, never stored**: the summary, pair, side, amounts, and price are
  computed from the transaction inside the signer. There is no summary or
  metadata field to tamper with.
- **Exact-pair enforcement**: offers must match an approved pair from
  `~/.xrpl/approved.json` exactly — token/token combinations that aren't
  listed are denied.
- **Per-asset spend limits**: per-transaction and true rolling-24h caps per
  asset (`spend_limits`), reserved atomically under a file lock so concurrent
  signers can't double-spend the daily budget. Assets with no configured
  limit are **blocked** (fail closed).
- **Ambiguity-safe reservations**: a reserved spend stays reserved (never
  double-spent, never released early) until the validated ledger result
  proves what happened. Unresolved liabilities are retained regardless of
  age — they never expire out of the rolling window. Proven non-inclusion
  (the node's complete history covers the full
  `[submit_ledger, LastLedgerSequence]` range) releases it; validated
  success confirms it; a validated *failure* releases the trade amount but
  retains the consumed fee as a confirmed XRP spend.
- **Strict accounting state**: spend state with negative, non-finite, or
  inconsistent entries fails closed (the signer refuses rather than silently
  resetting limits); `xrpl-sign recover-state` reconciles a damaged file
  without forgiving obligations.
- **Offer safety**: `Expiration` required and bounded by
  `max_offer_lifetime_seconds`; limit price within `max_deviation_bps` of a
  depth-weighted book reference (up to 10 levels per side) that requires
  both bid and ask sides, minimum depth (`min_book_depth`), and a maximum
  spread (`max_spread_bps`) — fail-closed on thin, one-sided, or wide
  books.
- **Destination policy**: payments only to allowlisted `(address,
  destination_tag)` combinations; conflicting X-address/CLI tags are
  rejected; destinations with `RequireDestTag` set refuse untagged payments
  (fail-closed on lookup errors).
- **Network lock**: default `testnet`. Mainnet proposals **hard-fail** until
  you explicitly opt in.
- **Protected files**: the signer refuses to run if the policy, allowlist,
  state, lock, audit, or autopilot files are not owner-only `0600`. This catches
  accidental exposure — it does not replace the privileged boundary below.
- **Crash-safe submission**: sign → bind the reservation to the signed hash
  and `LastLedgerSequence` → persist to the audit log → submit → wait for the
  validated result. A crash anywhere still leaves a reconciliation trail.
- **Seed-address match**: the seed's derived address must equal the
  transaction account's enabled master key or its validated on-ledger
  `RegularKey`, or signing is refused. Disabled master keys are rejected.
- **Offer liquidity on funded amounts**: the book reference uses
  `taker_gets_funded`/`taker_pays_funded` (not nominal offer sizes), with
  both sides read at one explicit validated ledger.

Every signed transaction is appended to `~/.xrpl/audit.log`
(hash, result, network — never secrets).

### The platform boundary (read this)

`--approve` is an *assertion*, not evidence of human approval. v0.5 is
mainnet-ready **only** when all of these hold:

- Muse requires real user confirmation for each signing use (a typed
  command is not consent by itself).
- The vault releases `XRPL_SEED` to the signer only on that genuine
  confirmation — the seed is never a hand-exported shell variable.
- The signer and the policy file sit behind a vault, separate OS identity,
  or privileged signing service the agent cannot rewrite.

A same-user local agent does **not** satisfy this boundary, even with
`0600` files: a same-UID process can read the signer's environment and
rewrite its policy and state. Same-user installs are testnet-only.

Without those platform guarantees, v0.5 is a hardened testnet tool — not
generically mainnet-safe. Three deployment profiles are documented in
`README.md` (Muse vault / Xaman-human / autonomous-experimental); the
design states all of this honestly in `SECURITY.md`.

## The ceremony (every write)

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → prints the full proposal + hash, e.g. a2c72140d080ca0f…
# → NOTHING is submitted.

# A human reviews the exact hash, then:
xrpl-sign --profile main --hash a2c72140d080ca0f --approve
# → profile + envelope verify → policy checks → sign → persist →
#   submit_and_wait → validated ledger result → audit log
```

Without `--approve`, `xrpl-sign` only checks policy and prints the
transaction-derived summary — it never signs. On mainnet `--profile`
is mandatory and must match the profile the proposal was built for.

## Policy (`xrpl-sign init-policy` creates `~/.xrpl/policy.json`, v4)

- `network_lock` — default `testnet`. The emergency brake.
- `spend_limits` — per-asset `{per_tx, per_day}` caps, e.g.
  `"XRP": {"per_tx": "25", "per_day": "100"}`,
  `"RLUSD.rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De": {"per_tx": "40", "per_day": "150"}`.
  Assets without an entry are blocked. (`xrpl-sign migrate-policy`
  upgrades an older file, keeping a `.v3.bak`.)
- `allowed_tx_types` — the safe trading types plus, for v0.5,
  `NFTokenMint`, `NFTokenCreateOffer`, and `NFTokenAcceptOffer` when the
  operator enables them.
- `destination_allowlist` — `[{address, destination_tag, added_at}]` pairs
  (empty = no payments). Entries added through the tooling are timestamped
  and every add/remove is written to the audit log. The signing ceremony
  flags Payments to destinations added within the last 24h with a loud
  **NEW DESTINATION** warning — a prompt-injected allowlist add followed by
  a quick-tapped proposal is the attack this catches.
- `max_fee_drops`, `max_deviation_bps`, `proposal_ttl_seconds`
  (proposals expire after 24h by default).
- `max_spread_bps` (default 1000), `min_book_depth` (default "5", in QUOTE
  units of funded depth per side), `max_offer_lifetime_seconds`
  (default 86400) — the book-quality and offer-lifetime bounds.
- `nft` — `{max_transfer_fee, max_mints_per_day, allowed_mint_flags,
  max_uri_bytes, allow_buy_offers, max_bid_xrp}` (defaults 10000 / 10 /
  [1, 8] / 256 / false / "10"). The **buy side** (`nft-buy` and `nft-bid`)
  is opt-in: set `nft.allow_buy_offers` to `true` deliberately, because
  accepting a sell offer spends XRP immediately and a bid locks XRP until
  it is accepted, cancelled, or expires. `max_bid_xrp` caps a single bid.
- Token (currency, issuer) identities are extracted from the transaction
  JSON itself, so passing a raw issuer can't bypass the allowlist. Tickers
  mean nothing on XRPL; issuers are the identity.
- `xrpl-sign migrate-policy` upgrades a v2 or v3 file (keeping a
  `.v3.bak`), filling in the new v0.4 fields with their defaults. v4 adds
  the `nft` section but does **not** widen `allowed_tx_types` — existing
  operators must deliberately add `NFTokenMint` / `NFTokenCreateOffer` /
  `NFTokenAcceptOffer` to enable NFTs (and set `nft.allow_buy_offers=true`
  for the buy side).

## NFTs (v0.5): mint, list, inventory, buy, bid

Minting is a deliberate **two-step** flow — pinning is an external write
and happens inside the approved action, never before it:

```bash
xrpl-trade nft-stage --file art.png --name "Neon Drift" \
    --description "Series 1, piece 3" --royalty-bps 1000
# → validates the artwork locally (approved media dir, size/type/sha256)
#   and writes a reviewable stage record. ZERO network calls.

# A human reviews the stage record, then approves the pin + proposal as
# one action. PINATA_JWT is injected for this single operation only
# (e.g. PINATA_JWT="$(vault read ...)" xrpl-trade nft-pin-and-propose …)
# — never exported into a shell, never stored, never logged:
xrpl-trade nft-pin-and-propose --stage <stage-id>
# → re-validates the file against the staged hash, pins art + metadata
#   under YOUR Pinata account, proposes NFTokenMint
```

```bash
xrpl-trade nft-list --token-id <64-hex-id> --price-xrp 25 \
    [--destination r...] [--expires-in 86400]
# → proposes an XRP-denominated SELL offer
```

```bash
xrpl-trade nft-inventory [r...]      # read-only: every NFT you own
xrpl-trade nft-buy --offer-index <64-hex>
# → verifies the SELL offer from the ledger (seller, ISSUER/minter, URI,
#   taxon), then proposes NFTokenAcceptOffer
xrpl-trade nft-bid --token-id <64-hex> --seller r... --price-xrp 5 \
    [--expires-in 86400]
# → proposes a BUY offer (bid); the bid XRP locks until accepted/cancelled/expired

xrpl-trade nft-send --token-id <64-hex> --to <favorite-name|r...> \
    [--expires-in 86400]
# → proposes a 0-XRP TRANSFER offer (gift, NOT a sale); the recipient
#   must accept before it expires
```

- **Bring your own Pinata.** Every operator uses their own account and
  JWT; the publisher hosts no one's media. See `references/nft-pinata.md`.
- Royalty is `--royalty-bps` (0–5000, default 1000 = 10%), immutable after
  mint; flags default to burnable + transferable.
- Listings are XRP-only in v1, always carry a ledger expiration, and are
  gated by `max_mints_per_day` (rolling 24h) plus `max_transfer_fee`.
- **Buying: verify the seller, not the picture.** `nft-buy` fetches the
  sell offer from the ledger and refuses buy offers, non-XRP amounts, and
  vanished offers. It prints the on-ledger **seller, issuer, token URI,
  and taxon** before proposing, and the signer re-verifies the offer at
  signing time — if the offer changed, signing is refused. Anyone can
  mint the same artwork, so check that the issuer is the artist you
  expect — the seller is only the current owner. The skill reports
  on-ledger facts; it never calls a token "authentic". Each NFT is one-of-one: there is no fungible order-book
  price check, and price sanity is the human's call.
- Accepting a sell offer spends XRP immediately: the offer's price plus
  fee runs through the per-transaction and rolling-24h spend caps.
- Bids need `nft.allow_buy_offers: true` and are capped by
  `nft.max_bid_xrp`; the bid XRP is reserved until the offer resolves.
- **Transfers are gifts, not sales.** `nft-send` proposes a 0-XRP transfer
  offer to a favorite name or r-address (`--to` resolves the name locally
  and prints the resolved address in the proposal). The recipient must
  accept before expiry; it spends 0 XRP beyond the fee, and the signer
  ceremony describes it as a transfer, never a sale. Policy allows a
  0-XRP offer only with the sell flag and a destination — 0-XRP offers
  without a destination, and 0-amount bids, are refused.
- Minting, listing, sending, buying, and bidding are separate writes —
  each needs its own proposal hash and its own human approval.

## Following artists (v0.5): favorites + what's new

Entirely read-only — no proposals, no signing, no approvals.

```bash
xrpl-trade favorites add lara r… --note "Neon Drift series"
xrpl-trade favorites list
xrpl-trade favorites rename lara larva
xrpl-trade favorites remove larva

xrpl-trade nft-new              # new mints since the last check
xrpl-trade nft-new --days 30    # explicit window (1-90); never moves the watermark
```

- Names are lowercase `[a-z0-9_-]`, 1–32 chars; addresses get the real
  base58-checksum validation. Stored in `~/.xrpl/favorites.json`
  (owner-only `0600`, covered by the signer's protected-file check).
- `nft-new` walks each favorite's `account_tx` for `NFTokenMint`s since
  its per-favorite watermark (first run: last 7 days), then advances the
  watermark to the validated ledger. `--days` is a pure window scan.
- Each new piece shows the token ID, mint time, taxon, decoded URI, the
  cheapest current listing price if any ("not listed" otherwise), and an
  `https://xrp.cafe/nft/<NFTokenID>` link.
- Favorite names also work wherever a read command takes an address
  (`nft-inventory lara`). Among writes, only `nft-send --to` accepts a
  name — it resolves against the local favorites file (case-insensitive)
  and prints the resolved address in the proposal; the destination is
  hash-bound in the envelope like everything else.

## Onboarding: the user profile

On first run — when `~/.xrpl/profile.json` doesn't exist — offer the
questionnaire before anything else. Ask conversationally, one or two
questions at a time, then save the answers with the `profile` commands.
`xrpl-trade profile init` also runs it in a terminal.

```bash
xrpl-trade profile init                 # interactive questionnaire
xrpl-trade profile show                 # review it anytime
xrpl-trade profile set display_name "Mike"
xrpl-trade profile set alerts.price_moves true
xrpl-trade profile set alerts.threshold_pct 3
xrpl-trade profile add-address r…       # WATCH-ONLY. Never a seed.
xrpl-trade profile add-membership xaodao
xrpl-trade profile add-interest trading
xrpl-trade profile remove-interest trading
xrpl-trade profile clear                # start over
```

What to ask: what to call them; watch-only XRPL addresses; DAO
memberships (open list — `xaodao`, whatever they hold); what they use
the skill for (`trading`, `nfts`, `dao-governance`, `discovery`, …);
whether they want price-move alerts and at what threshold.

**The seed rule (non-negotiable):** NEVER ask for a seed, secret key,
or passphrase — ask for the watch-only classic address (starts with
`r`). If the user pastes anything seed-like, STOP: warn them loudly,
save nothing, and move on. The CLI enforces this too — `add-address`
refuses seed-shaped input with an explicit warning and never stores it.

- Stored in `~/.xrpl/profile.json`, owner-only `0600`, schema-versioned
  (`schema_version: 1`). Local only — it never leaves the machine.
- The profile drives personalization: `memberships` feeds reminders
  (e.g. `xaodao` → DAO proposal vote reminders), `alerts.*` feeds
  price-move alerts, `interests` shapes menus and suggestions.
- Keep the public skill generic: memberships and interests are open
  tag lists, never hardcoded to one DAO or one user.

## Friday community giveaway

Every Friday at 7:37 AM, one random entrant wins a gift — funded by the
community, drawn in public, verifiable by anyone. This skill covers entry,
eligibility, the draw, the gift proposal, and the announcement draft. The
scheduled Friday run lives on a cron; every gift stays human-approved, one
at a time — **no automatic signing or sending, ever**.

The pot: the **Musegives** donation wallet
`rnkt27oqgJiRfsuwCogqrLwYx4NNooMFdB` (public by design — publishing it is
how people find the pot). Anyone can contribute XRP to it.
`~/.xrpl/giveaway.json` (owner-only `0600`) holds the donation wallet and
the opt-in tag (defaults: Musegives, tag `777`), plus `max_gift_xrp`
(default `10` — the largest XRP gift the tool will propose) and
`network` (default `mainnet`). Every giveaway command takes
`--donation-wallet r…`, so community leaders can run the same flow
against their own wallet with no code changes.

### Opting in: 1 drop, destination tag 777

Entry is a single Payment of exactly **1 drop** (0.000001 XRP) to the
donation wallet with destination tag **777** — it proves the entrant owns
the address and costs ~nothing. `profile init` offers this as its last
question (default: skip — silence is never consent). Answering yes first
checks for an existing on-ledger opt-in, then adds the exact
(donation wallet, tag 777) pair to the payment destination allowlist and
creates a normal 1-drop Payment **proposal**. The human still approves it,
and the profile is marked opted-in (`giveaway.opt_in: true` +
`giveaway.opt_in_tx`) only after the payment is **validated on-ledger** —
re-run `giveaway opt-in` after approving to record it. Creating a proposal
is never treated as opt-in.

```bash
xrpl-trade giveaway opt-in                 # check for an entry, else PROPOSE one
xrpl-trade giveaway entrants [--donation-wallet r…]
xrpl-trade giveaway draw [--donation-wallet r…] [--ledger-offset N]
xrpl-trade giveaway status [--donation-wallet r…]
```

### Eligibility + the draw

- `entrants` scans the donation wallet's `account_tx` for incoming
  successful Payments of exactly 1 drop with tag 777. Each entrant needs
  ≥1 wallet action besides the opt-in itself: `OfferCreate`,
  `OfferCancel`, non-opt-in `Payment`, `TrustSet`, `NFTokenMint`,
  `NFTokenCreateOffer`, `NFTokenAcceptOffer`, `NFTokenCancelOffer`.
- `draw` waits for validated ledger index + `--ledger-offset` (default
  20), takes that future ledger's hash, and computes
  `sha256(ledger_hash + ":" + opt-in tx hashes in address order) mod
  entrants`. It prints the winner, the ledger index/hash, the digest,
  and the method — anyone can recompute it independently. **Selection
  only: no gift proposal is built, signed, or sent.**
- `status` shows the pot: XRP balance, nonzero trustlines, owned NFTs.
- `draw` saves its public proof to `~/.xrpl/giveaway_last_draw.json`
  (ledger index/hash, method, digest, winner) so the announcement can be
  recomputed later.

### Gifting the prize (always propose → human `--approve` → sign)

`gift` builds the prize proposal from the donation wallet — XRP, an IOU,
or an NFT. It never signs and never sends; the human approves that exact
proposal hash, then the donation wallet's key signs it. Three forms:

```bash
xrpl-trade giveaway gift --to rWinner… --amount 5            # 5 XRP
xrpl-trade giveaway gift --to rWinner… --amount 25 --ccy USD --issuer r…
xrpl-trade giveaway gift --to rWinner… --token-id <64-hex>   # 0-XRP NFT transfer offer
```

- Exactly one of `--amount` / `--token-id`. XRP is the default currency;
  IOU gifts need `--issuer`. NFT gifts are 0-XRP transfer offers to the
  winner with a 24h expiry (the wallet must actually own the NFT).
- IOU gifts are doubly fail-closed at signing: the token must already be
  in the approved token allowlist (`approved.json`) **and** have a
  `spend_limits` entry in the giveaway policy — both deliberate human
  edits, so no surprise token ever leaves the pot.
- Guards: `--to` must be a valid classic address and cannot be the
  donation wallet itself; anything seed-like is refused with a loud STOP
  (a seed is never a destination). XRP gifts above `max_gift_xrp` are
  refused — the cap is raised by editing `~/.xrpl/giveaway.json`
  deliberately, never in the heat of the moment. A winner who hasn't
  opted in gets a warning, not a block (Mike's call can override).
- `setup` (interactive, local): writes the narrow giveaway signer policy
  (`~/.xrpl/giveaway_policy.json` — only `Payment` +
  `NFTokenCreateOffer`, network-locked, XRP spend capped at
  `max_gift_xrp`, arbitrary winner destinations since the human approved
  the exact one). It then offers to store the donation wallet's seed:
  the preferred path is the `XRPL_GIVEAWAY_SEED` environment variable
  (injected from the secure vault for the exact approved moment); the
  fallback is a hidden prompt that stores it in `~/.xrpl/giveaway.json`
  (`0600`). Either way the seed is never printed, logged, or echoed —
  the CLI verifies it derives the configured donation address before
  storing anything. The local fallback is deliberate and explicit, and
  `xrpl-sign`'s `check_protected_files` covers `giveaway.json` and the
  giveaway policy in giveaway mode — the signer refuses to run if either
  is not owner-only.
- `announce [--winner r…] [--prize "5 XRP"]` prints a draft winner
  announcement from the last draw (winner, prize, ledger index/hash,
  method, digest, entrant count, pot address, next Friday 7:37 AM). It
  posts nothing — the draft is for review.
- The proposal prints its giveaway signing command:
  `xrpl-sign --hash <hash> --approve --seed-env XRPL_GIVEAWAY_SEED
  --policy ~/.xrpl/giveaway_policy.json` (the `--approve` flag is never
  the approval — the human's explicit go-ahead for that exact hash is).

The Friday flow: cron runs `giveaway draw` → Mike picks the prize →
`giveaway gift` builds the proposal → he approves that exact hash → the
signer signs with the donation wallet's key under the giveaway policy →
a validated-ledger result closes it → `giveaway announce` drafts the
post. `draw` never transacts, and neither does `gift` on its own.

## XRPresso discovery: marketplace search (read-only)

XRPresso (xrpresso.io) is a non-custodial P2P marketplace on XRPL —
goods, gigs, music, NFTs. Its free Discovery API v1 needs no key and
no signup; the skill searches it straight from chat.

```bash
xrpl-trade xrpresso listings --q "neon" --sort newest
xrpl-trade xrpresso listings --category art --currency XRP --limit 10
xrpl-trade xrpresso nfts --q "drift" --sort price_asc
xrpl-trade xrpresso auctions
xrpl-trade xrpresso listing <id>     # full detail for one listing
xrpl-trade xrpresso stats            # marketplace aggregates
xrpl-trade xrpresso categories       # category keys for --category
```

- Human-in-the-loop by design: the agent finds, the human buys.
  Every result prints its XRPresso deep link (with `?ref=api_v1`
  attribution preserved) — open it to buy/bid in XRPresso's UI and
  sign in your own wallet. The v1 API has no buy/mint/offer/escrow
  endpoints and the skill never recreates them.
- Deep links are validated before display: only `https` URLs on
  `xrpresso.io` (or a subdomain) are shown; anything else is withheld,
  never printed.
- Polite by construction: ≥3s between calls (well under the platform's
  30/min IP limit), 15s timeout, 1MB response cap. No policy changes,
  no approvals, no `~/.xrpl` writes — this feature cannot spend.
- Honest limits: the catalog is small and early-stage; XRPresso is a
  listings marketplace, not a trading venue — there are no swap
  endpoints. For token swaps the skill's own DEX flow is the tool.

## Community directory (reference)

`references/xrpl-community-directory.md` is a curator-maintained directory
of XRPL community members, projects, tools, wallets, media, XRP Café
creator profiles, and public account addresses — with per-entry
verification labels (curator-identified vs unverified association).

Consult it when the user asks "who is X", wants an X handle or project
website, or needs an XRP Café profile link. It also records the issuers
of the curator's approved trading-pair tokens.

Hard rules, from the file's own header — never weakened:

- Every entry is reference data, not an endorsement, allowlist, identity
  proof, or payment instruction.
- Never initiate, prepare, recommend, or auto-fill a transaction from an
  address in this directory alone. If the user wants to pay, tip, or
  gift someone named here, they paste or confirm the address themselves;
  the agent never fills it from the file.
- Before displaying an address as belonging to a person or project,
  confirm it from an official source or describe the association as
  unverified.

## Menu presentation (standard)

When presenting this skill in chat, **always use clickable button menus
by default** — not raw command lists. The user navigates by tapping,
not by typing commands.

**Main menu buttons:**
- XRPL Actions
- NFT
- Artists
- Wallets
- XRP News
- XRPLF
- Coffee & Crypto
- xBoost

Each button opens its own focused submenu of tappable exact-command
buttons. After showing command results, attach a fresh set of the most
useful follow-up commands as buttons.

The `xrpl-trade menu` command provides the same navigation in a
terminal (arrow-key navigable). But in chat, buttons are the standard.

## Commands

Reading (no seed, no proposals):

- `balance [address]` — XRP + trustline balances
- `quote --pair ARMY/XRP` — order book top-of-book, any pair
- `offers [address]` — open offers
- `pairs` — approved pairs
- `inspect-token --currency FUZZY --issuer r…` — issuer risk: domain,
  transfer fee, global-freeze / no-freeze flags
- `plan-trade --pair ARMY/XRP --side buy --amount 1000 --price 0.005` —
  estimated fill, price impact vs mid, max spend (read-only)
- `reconcile --hash …` — validated outcome of a submitted transaction
- `nft-inventory [r…]` — every NFT owned by an account (read-only);
  accepts a favorite name too (`nft-inventory lara`)
- `favorites add|remove|list|rename` — named watchlist of artist wallets
  (local only, no network, no approval)
- `nft-new [--days N]` — new mints from your favorites since the last
  check, with listing prices and xrp.cafe links (read-only)
- `xrpresso listings|nfts|auctions|listing|categories|stats` — search
  the XRPresso marketplace (read-only, no key, no signup); results
  print deep links so you buy/bid in XRPresso's UI
- `giveaway entrants|draw|status|announce [--donation-wallet r…]` —
  opt-ins + eligibility, the deterministic draw (**selection only — no
  gift is built or sent**), the pot: XRP balance, nonzero trustlines,
  NFT inventory, and a draft winner announcement from the last draw
  (read-only, nothing posted)

Local wallet management (local-only, explicit opt-in — see "Wallets"):

- `wallet create [--force]` — generate a fresh wallet; seed stored 0600,
  never displayed
- `wallet backup` — ONE-TIME seed display for write-down; requires typing
  `I HAVE WRITTEN IT DOWN`, records `seed_backed_up` in config.json

Writing (always propose → human `--approve` → sign):

- `buy --pair P --amount A --price Px` — buy BASE with QUOTE at limit
- `sell --pair P --amount A --price Px` — sell BASE for QUOTE at limit
- `trustline --pair P --limit N` — trustline the pair's base token
- `cancel --seq N` — cancel an open offer
- `send --to r… --amount A --ccy XRP [--destination-tag N]`
- `nft-send --token-id <64-hex> --to <favorite|r…>` — gift an owned NFT
  (0-XRP transfer offer; recipient must accept before expiry)
- `giveaway opt-in [--donation-wallet r…]` — PROPOSE the 1-drop entry
  payment to the donation wallet (tag 777); recorded as opted-in only
  after the payment validates on-ledger
- `giveaway gift --to r… --amount A [--ccy XRP] [--issuer r…]` |
  `--token-id <64-hex> [--donation-wallet r…]` — PROPOSE the prize from
  the donation wallet (XRP under `max_gift_xrp`, an IOU, or a 0-XRP NFT
  transfer offer); signs only after the human approves that exact hash
  with the donation wallet's key (`--seed-env XRPL_GIVEAWAY_SEED`) under
  the giveaway policy

`--amount` is always BASE units, `--price` is always QUOTE per BASE.
`--pair NAME` resolves through `~/.xrpl/approved.json` (copy
`approved.example.json` there and add vetted issuers). Explicit
`--base/--quote/--base-issuer/--quote-issuer` also works — but the signer
still enforces the allowlist on the resulting tokens.

## Setup

```bash
pip install -r requirements.txt
xrpl-trade setup            # onboarding: generate a wallet, or register an address
xrpl-sign init-policy       # writes ~/.xrpl/policy.json (testnet-locked)
```

The signer reads the seed **only** from `XRPL_SEED`, provided by your
secret manager or the Muse vault after human approval. Fund a testnet
wallet: `xrpl-trade faucet --network testnet`.

## Wallets (v0.7): vault-only mainnet, local testnet

Mainnet keys are created and backed up in your vault (password manager),
outside this tool — the CLI refuses to create or display mainnet seeds:

- `wallet create --network mainnet` → refused (use the vault).
- `wallet backup --network mainnet` → refused (the vault is the backup).
- The signer refuses mainnet while legacy seeds remain on disk
  (`wallet forget-seed` removes one only after you type the address to
  confirm the vault backup exists).

**Exception — Autopilot (explicit opt-in only):** `xrpl-trade autopilot
enable` deliberately stores one wallet's seed on disk (owner-only 0600)
after the operator types `ENABLE AUTOPILOT` under a plain-language risk
disclosure. See "Autopilot — at your own risk" above. This is the
documented weaker deployment mode for a dedicated limited-funds wallet —
never the main vault wallet.

Testnet keeps the convenient local flow: `wallet create` generates a fresh
ed25519 wallet (seed to `~/.xrpl/config.json`, 0600, atomic) and prints
only the address; the faucet writes its seed to a dedicated file, never to
the terminal. `setup` offers generation (default: no — silence is never
consent); `create` refuses to overwrite without `--force`. The audit log
records `wallet_create` / `wallet_backup` / `wallet_forget_seed` events
without seed material.
If a seed ever touches chat or a log, treat the wallet as burned and
generate a new one — exposure can't be undone.

## Funding a wallet (fiat on-ramp, optional)

If the wallet has no XRP yet — or the user wants to buy with a credit/debit
card — fund it first via the companion `changelly_buy` skill. See
`references/fiat-onramp.md` for the exact commands.

The on-ramp sits **outside** the propose → approve → sign boundary: it only
generates a buy link, never sees the seed, and never submits ledger
transactions. The buyer completes KYC and payment on Changelly; once the XRP
lands, continue with the normal ceremony above.

## Safety rules for the operator

- Start on testnet. Opt into mainnet in the policy file deliberately.
- Trade from a dedicated limited-funds wallet.
- Always review the proposal hash yourself before `--approve`.
- `tesSUCCESS` from submission is provisional until the validated ledger
  confirms it — `xrpl-sign` waits and reports the validated result.
- See `SECURITY.md` for the disclosure policy, the platform boundary, and
  the pre-`c3273e59` buy/sell inversion advisory.

## Layout

- `bin/xrpl-trade` — proposer (builds + previews, never signs)
- `bin/xrpl-sign` — policy-gated signer
- `bin/xrpl_common.py` — shared helpers (envelopes, policy, allowlist, limits)
- `tests/test_v04.py` — 78 adversarial logic tests, no network needed
- `tests/test_nft.py` — 104 NFT adversarial tests, no network needed
- `tests/test_favorites.py` — 67 favorites + nft-new unit tests, no network
- `tests/test_e2e_testnet.py` — 52 end-to-end checks on testnet
  (propose → approve → sign → persist → validated), fully isolated in a
  temporary HOME — never touches the operator's real `~/.xrpl`
