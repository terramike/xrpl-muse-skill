## Commands

Reading (no seed, no proposals):

- `balance [address]` — XRP + trustline balances
- `quote --pair ARMY/XRP` — order book top-of-book, any pair
- `offers [address]` — open offers
- `pairs` — approved pairs
- `movers [--view gainers|losers|volume|trending] [--limit 10]` — xrpl.to
  token rankings (read-only). Rows show XRP price, 24h %, 24h volume,
  and market cap. "Data by xrpl.to" credit on every row set.
- `token-lookup --issuer r… --currency CODE` — one-screen token brief:
  XRP + USD price, market cap, holders, trustlines, 24h/7d change,
  24h volume, verified badge, plus the scam-check + risk score.
  Read-only; carries the "Data by xrpl.to" credit.
- `tx-explain --hash <64-hex>` — ledger-derived facts for a transaction
  (type, account, status, fee, date). Prints xrpl.to's plain-English
  summary only when the API actually returns one — never invented.
- `inspect-token --currency FUZZY --issuer r…` — issuer risk: domain,
  transfer fee, global-freeze / no-freeze flags
- `token-safety --currency FUZZY --issuer r…` — xrpl.to scam blocklist
  check + 1–10 token risk score for an IOU (read-only, no key needed).
  Advisory only: a hit is LOUD but never blocks; the human decides.
  Buy/sell proposals run this automatically on every IOU leg
  (`--no-safety` skips). Surfaces carry a "Data by xrpl.to" credit.
- `xrpl_to.py nft-safety --nft-id <64-hex> [--ask-xrp 40]` — NFT
  buy-side safety: issuer scam-blocklist screen, tracked collection +
  floor (24h-ago floor), asking-price × floor multiple, cheapest live
  ask, and approx last sale from ledger history. `nft-buy` and `nft-bid`
  proposals run this automatically (`--no-safety` skips); every line is
  advisory — floors and last-sales can be wash-traded, and the on-ledger
  seller/issuer/URI/taxon verification stays the authority. Fail-open:
  an unreachable API prints UNAVAILABLE (unknown, not clean).
- `xrpl_to.py whale-watch --issuer r… --currency CODE [--limit 10]` —
  token trader discovery (read-only): top wallets ranked by 24h volume,
  with 24h trade counts and 24h P&L. Flow discovery, not advice —
  volumes are wash-tradable; carries the "Data by xrpl.to" credit.
- `xrpl_to.py incoming-offers --account r… [--limit 10]
  [--collection text] [--min-xrp N] [--max-xrp N] [--from name-or-address]
  [--include-flagged] [--no-safety]` — open NFT offers for an account:
  bids on its NFTs plus sell/gift offers directed at it, newest first,
  with floor context and a per-row issuer blocklist screen. Flagged
  offers hidden by default (count shown). `xrpl-trade incoming` wraps
  this with recent ledger receipts and your favorite labels.
  Read-only; "Data by xrpl.to" credit.
- `xrpl_to.py keys create --yes` — mint a free xrpl.to API key via a
  wallet-signed login message (nothing submitted on-chain; key stored
  0600 at `~/.xrpl/xrplto.json`). Raises rate limits; most endpoints
  work without a key. Creating a key accepts xrpl.to's API terms.
  `keys list` shows keys on the wallet; `keys revoke --id … --yes`
  revokes one (both wallet-signed; free tier allows one active key,
  so revoke-then-create rotates).
- `plan-trade --pair ARMY/XRP --side buy --amount 1000 --price 0.005` —
  estimated fill, price impact vs mid, max spend (read-only)
- `farm about` — Farmers Union ($FARM) explainer: harvesting, crop
  dusting, the Farm Assured Guarantee, how to qualify (static,
  `references/farm.md`, no network)
- `farm links` — clean link bundle: farmerunion.meme, the barn trustline
  checker, the $FARM token page, the Animal Fam NFT collection, issuer +
  treasury addresses (static, no network)
- `farm qualify [address]` — 123,000 FARM qualification check: FARM
  balance + LP-token FARM-equivalent (each AMM valued individually via
  `amm_info`, fail-open) vs the threshold, plus a trustline audit against
  the cropdusting board. Defaults to the first profile address. Read-only.
- `farm treasury` — live read of the 4 published Farmers Union wallets
  (XRP + FARM each, fail-open per wallet) vs their published ~$148,150
  site figure (2026-09-30). Read-only.
- `farm dustings [--refresh]` — the cropdusting board: upcoming ("set
  your trustlines") vs completed, from a lazy local cache
  (`~/.xrpl/farm-dustings.json`, refreshed when older than 7 days).
  Every render prints its data-as-of date. The Union's own disclaimer —
  inclusion is not an endorsement — is printed too; screen any issuer
  with `token-safety` before trusting it. Read-only.
- Every `farm` command ends with a one-paragraph shareable summary
  (farmers research *and* post with this skill).
- `reconcile --hash …` — validated outcome of a submitted transaction
- `trace <address> [--depth N]` — funding-origin trace: who funded this
  account, and who funded them (default 2 hops, max 3). Prints first-seen
  ledger, funder, amount, tx hash, plus control signals (RegularKey,
  signer list, domain). Light by design: hard RPC-call budget, 1h local
  cache, fail-open. Output discipline: `LINK:` = on-ledger fact,
  `NOTE:` = caveat; never claims ownership.
- `links <addressA> <addressB> [--window N]` — shared counterparties,
  shared trustline issuers, shared tokens (with issuer transfer-fee /
  freeze flags), and control overlap (same RegularKey, shared
  signer-list members) from the N most recent validated txs per account
  (default 200, max 500). Exchange hot wallets can appear as shared
  counterparties — the known-address label registry (`LABEL:` lines,
  `references/known-labels.json` + your `~/.xrpl/labels.local.json`
  overrides) marks them, and every command reminds you that links
  through service wallets are usually plumbing, never proof of common
  control. See `references/forensic-mode.md`.
- `flow <address> [--window N]` — top counterparties by volume in/out
  over the recent window (default 200, max 500): delivered amounts for
  Payments, executed fills attributed to makers for DEX trades. Ranked
  by XRP volume; wash-tradable, so it's discovery, not proof.
- `nft-trail <token-id>` — NFT provenance: mint → offers →
  transfers/sales → currently held by (via `nft_history`, with a
  bounded issuer-scan fallback). On-ledger chain only.
- `token-trail --issuer r… --currency CODE [--window N]` — issuer
  profile (domain, transfer fee, freeze flags), top holders from a
  bounded — explicitly partial — trustline scan, and top movers by
  token volume in the window (issuer-involved flow only — issuance,
  redemption, rippling through the issuer; ordinary holder-to-holder
  transfers are invisible to this scan).
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

