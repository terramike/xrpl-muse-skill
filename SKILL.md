# xrpl-muse-skill

Trade the XRP Ledger from the terminal — any token pair, with a hard safety
boundary between proposing a trade and signing it.

## Architecture: propose → approve → sign (v0.5)

Two programs. The agent only ever runs the first.

1. **`xrpl-trade` — the proposer.** Builds transactions, autofills them against
   the live network, prints the full ceremony (account, network, assets with
   issuers, amounts, limit price, max spend, fee, sequence, expiry), and saves
   a **hash-bound proposal envelope**. It **never sees the seed** and **never
   submits**.
2. **`xrpl-sign` — the policy-gated signer.** The only program that touches the
   seed (from the `XRPL_SEED` env var — never from a config file). It verifies
   the proposal envelope, enforces `~/.xrpl/policy.json`, derives the summary
   from the transaction itself, and signs **only** when a human passes
   `--approve` for that exact hash.

### The envelope (what the hash binds)

A proposal is `format: xrpl-proposal/3` and the approval hash covers:

- `network`, `account`, `action`, `created_at`, `policy_version`
- the **canonical XRPL binary** of the complete transaction
  (`xrpl.core.binarycodec.encode`)

The signer re-verifies all of it and rejects anything tampered with —
including the envelope file itself. Old-format proposals are rejected;
rebuild them with the current `xrpl-trade`.

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
  proves what happened; proven non-inclusion releases it, validated success
  confirms it.
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
  state, lock, or audit files are not owner-only `0600`. This catches
  accidental exposure — it does not replace the privileged boundary below.
- **Crash-safe submission**: sign → bind the reservation to the signed hash
  and `LastLedgerSequence` → persist to the audit log → submit → wait for the
  validated result. A crash anywhere still leaves a reconciliation trail.
- **Seed-address match**: the seed's derived address must equal the
  proposal's account, or signing is refused.

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

Without those platform guarantees, v0.5 is a hardened testnet tool — not
generically mainnet-safe. The design states this honestly; see `SECURITY.md`.

## The ceremony (every write)

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → prints the full proposal + hash, e.g. a2c72140d080ca0f…
# → NOTHING is submitted.

# A human reviews the exact hash, then:
xrpl-sign --hash a2c72140d080ca0f --approve
# → envelope verify → policy checks → sign → persist → submit_and_wait
# → validated ledger result → audit log
```

Without `--approve`, `xrpl-sign` only checks policy and prints the
transaction-derived summary — it never signs.

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
- `destination_allowlist` — `[{address, destination_tag}]` pairs
  (empty = no payments).
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

```bash
export PINATA_JWT="…"   # your own Pinata account — never goes in git
xrpl-trade nft-mint --file art.png --name "Neon Drift" \
    --description "Series 1, piece 3" --royalty-bps 1000
# → pins art + metadata under YOUR Pinata account, proposes NFTokenMint

xrpl-trade nft-list --token-id <64-hex-id> --price-xrp 25 \
    [--destination r...] [--expires-in 86400]
# → proposes an XRP-denominated SELL offer
```

```bash
xrpl-trade nft-inventory [r...]      # read-only: every NFT you own
xrpl-trade nft-buy --offer-index <64-hex>
# → verifies the SELL offer from the ledger, then proposes NFTokenAcceptOffer
xrpl-trade nft-bid --token-id <64-hex> --seller r... --price-xrp 5 \
    [--expires-in 86400]
# → proposes a BUY offer (bid); the bid XRP locks until accepted/cancelled/expired
```

- **Bring your own Pinata.** Every operator uses their own account and
  JWT; the publisher hosts no one's media. See `references/nft-pinata.md`.
- Royalty is `--royalty-bps` (0–5000, default 1000 = 10%), immutable after
  mint; flags default to burnable + transferable.
- Listings are XRP-only in v1, always carry a ledger expiration, and are
  gated by `max_mints_per_day` (rolling 24h) plus `max_transfer_fee`.
- **Buying: verify the seller, not the picture.** `nft-buy` fetches the
  sell offer from the ledger and refuses buy offers, non-XRP amounts, and
  vanished offers. It prints the on-ledger **seller, token URI, and
  taxon** before proposing, and the signer re-verifies the offer at
  signing time — if the offer changed, signing is refused. Anyone can
  mint the same artwork, so check that the seller is the minter you
  expect. The skill reports on-ledger facts; it never calls a token
  "authentic". Each NFT is one-of-one: there is no fungible order-book
  price check, and price sanity is the human's call.
- Accepting a sell offer spends XRP immediately: the offer's price plus
  fee runs through the per-transaction and rolling-24h spend caps.
- Bids need `nft.allow_buy_offers: true` and are capped by
  `nft.max_bid_xrp`; the bid XRP is reserved until the offer resolves.
- Minting, listing, buying, and bidding are separate writes — each needs
  its own proposal hash and its own human approval.

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
  (`nft-inventory lara`). Writes never accept names — exact addresses
  only.

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

Writing (always propose → human `--approve` → sign):

- `buy --pair P --amount A --price Px` — buy BASE with QUOTE at limit
- `sell --pair P --amount A --price Px` — sell BASE for QUOTE at limit
- `trustline --pair P --limit N` — trustline the pair's base token
- `cancel --seq N` — cancel an open offer
- `send --to r… --amount A --ccy XRP [--destination-tag N]`

`--amount` is always BASE units, `--price` is always QUOTE per BASE.
`--pair NAME` resolves through `~/.xrpl/approved.json` (copy
`approved.example.json` there and add vetted issuers). Explicit
`--base/--quote/--base-issuer/--quote-issuer` also works — but the signer
still enforces the allowlist on the resulting tokens.

## Setup

```bash
pip install -r requirements.txt
xrpl-trade setup            # address + network only (never the seed)
xrpl-sign init-policy       # writes ~/.xrpl/policy.json (testnet-locked)
```

The signer reads the seed **only** from `XRPL_SEED`, provided by your
secret manager or the Muse vault after human approval. Fund a testnet
wallet: `xrpl-trade faucet --network testnet`.

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
