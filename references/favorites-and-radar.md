## Following artists (v0.5): favorites + what's new

Entirely read-only — no proposals, no signing, no approvals.

```bash
xrpl-trade favorites add lara r… --note "Neon Drift series"
xrpl-trade favorites add jenna r… --kind friend --label "Jenna X"
xrpl-trade favorites list
xrpl-trade favorites rename lara larva
xrpl-trade favorites remove larva

xrpl-trade nft-new              # new mints since the last check
xrpl-trade nft-new --days 30    # explicit window (1-90); never moves the watermark
xrpl-trade nft-new --limit 10   # show newest 10 per artist (default 25; 0 = no cap)
xrpl-trade nft-new --no-safety  # skip the xrpl.to enrichment

xrpl-trade fuzzy-deals            # FUZZY NFTs below the sample median ask
xrpl-trade fuzzy-deals --threshold 30  # flag asks 30%+ below median (1-90)
xrpl-trade fuzzy-deals --json    # machine-readable output
```
- `fuzzy-deals` is read-only: it scans the FUZZY community collections
  (`fuzzybears` — the official project issuer Mike confirmed — plus
  `fuzzy-bars`), pulls listed tokens and each token's live sell offers via
  xrpl.to, and flags asks at least `--threshold` percent below the
  collection's trimmed median ask (top/bottom quartiles chopped so whale
  listings can't drag the reference). Each deal also shows its percentile
  rank ("cheaper than N% of asks") — the honest signal when discounts look
  dramatic. Stats are per-collection samples — never full-collection
  facts, never "worth." Acting on a deal is the separate
  `nft-buy --offer-index` ceremony; the scanner never buys, bids, or moves
  funds. Market data carries the "Data by xrpl.to" credit. Every XRP figure
  also shows its USD equivalent at the current Bitstamp XRP/USD rate
  (XRP-denominated asks mean different dollars as XRP moves; XRP stays
  primary, USD is parenthetical context).

- Names are lowercase `[a-z0-9_-]`, 1–32 chars; addresses get the real
  base58-checksum validation. Stored in `~/.xrpl/favorites.json`
  (owner-only `0600`, covered by the signer's protected-file check).
- Favorites have a `kind`: `artist` (default), `friend`, or `watch`, plus an
  optional `label` — the plain display name shown next to the address
  ("Jenna X (rABC…WXYZ)"). Labels accept plain letters, numbers,
  spaces, and basic punctuation only; emoji and stylized Unicode are
  rejected. Labels are local notes — not proof of who owns a wallet.
- `nft-new` walks each **artist** favorite's `account_tx` for
  `NFTokenMint`s since its per-favorite watermark (first run: last 3
  days), then advances the watermark to the validated ledger. Friend
  favorites are never scanned — they're just labels. `--days` is a
  pure window scan. `--limit N` shows only the newest N mints per artist
  (default 25, 0 = no cap); older mints beyond the cap are counted, not
  listed, and the watermark still advances past them.
- Each new piece shows the token ID, mint time, taxon, decoded URI, the
  cheapest current listing price if any ("not listed" otherwise), an
  `https://xrp.cafe/nft/<NFTokenID>` link, and a one-line xrpl.to
  safety note (issuer scam-blocklist screen + collection/floor,
  advisory, fail-open; max 20 enriched per run, later rows say so;
  `--no-safety` skips). "Data by xrpl.to" credit on every run.
- `xrpl-trade incoming [--account r…] [--watch name] [--all-watched]
  [--limit 10] [--collection text]
  [--min-xrp N] [--max-xrp N] [--from name-or-address] [--include-flagged]
  [--no-safety]` — what's coming IN, read-only: (1) open NFT offers —
  bids on your NFTs plus sell/gift offers directed at you, with a
  per-row issuer blocklist screen and floor-vs-bid context; (2) recent
  ledger receipts/sends from `account_tx` (direction derived from the
  consumed offer, the validated ledger as authority). Flagged offers
  are hidden by default (the count is shown). Counterparties render
  through favorite labels where you have them — an unlabeled wallet
  gets a 🏷️ "label this wallet" follow-up button. Accepting an offer
  stays a separate `nft-buy` propose → approve → sign ceremony; offers
  can be cancelled, so the ledger is authoritative before you act.
  Zero-XRP offers from wallets you don't recognize print a loud
  caution: only accept those from people you know.
  `--watch name` / `--all-watched` read from the watched-wallet list below.
- **Watched wallets + offer reminders** (read-only, addresses only — a
  seed can never pass the address checksum, so one can never be stored):
  ```bash
  xrpl-trade watch add studio-vault r… --label "Studio Vault"
  xrpl-trade watch list
  xrpl-trade watch remove studio-vault
  xrpl-trade watch check        # sweep for NEW open offers, offers only
  ```
  `watch check` queries the xrpl.to offers API per watched wallet, diffs
  offer indices against a local watermark
  (`~/.xrpl/hidden_files/watch-seen.json`, `0600`), and prints only NEW
  offers — the first run per wallet seeds the baseline silently. An
  hourly reminder job runs `watch check` and pings chat only when new
  offers appear; acting on one is still the manual `nft-buy` ceremony.
- Favorite names also work wherever a read command takes an address
  (`nft-inventory lara`). Among writes, only `nft-send --to` accepts a
  name — it resolves against the local favorites file (case-insensitive)
  and prints the resolved address in the proposal; the destination is
  hash-bound in the envelope like everything else.

