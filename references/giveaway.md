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

