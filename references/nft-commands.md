## NFTs (v0.5+): collections, templates, mint, list, inventory, buy, bid

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

### Collections, templates & attribution (v0.9)

Saying "mint an nft" starts a guided chat, not a one-shot command: the
assistant walks through **collection → template/ad-hoc fields → artwork
→ values → review**, then the usual stage → pin → propose → approve →
sign flow. Collections and templates are plain local JSON registries —
there is no on-ledger "collection" object; a collection is just a named
**issuer + NFTokenTaxon** pair you reuse, and a template is a reusable
field schema (v1: string fields only) that is **not** bound to any
collection — you pick both fresh at each mint.

```bash
# Register a collection LOCALLY (no ledger transaction — it exists
# on-ledger only once you mint into its issuer+taxon):
xrpl-trade collection create --name jets --taxon 200 \
    [--issuer r...] [--royalty-bps 1000] [--description "..."]
xrpl-trade collection list
xrpl-trade collection inspect jets   # issuer, taxon, on-ledger token count
xrpl-trade collection remove jets

# Reusable metadata field schemas (string values, v1):
xrpl-trade template create --name jets \
    --field "attack:required" --field "speed:required" --field "gun1"
# (omit --name/--field for an interactive walkthrough)
xrpl-trade template list
xrpl-trade template show jets
xrpl-trade template remove jets

# Mint into a collection with a template; extra fields ad-hoc:
xrpl-trade nft-stage --collection jets --template jets \
    --meta attack=90 --meta speed=75 --meta gun1=railgun \
    --file art.png --name "Jet #1"
# --royalty-bps overrides the collection's default royalty;
# --taxon is refused together with --collection (the collection owns it);
# --issuer is for authorized-minter mints (below).
```

- Registry files live in `~/.xrpl/` (`collections.json`,
  `nft-templates.json`), written temp-file + atomic rename, mode `0600`.
  The assistant treats `collection create/remove` and `template
  create/remove` like policy edits: it shows the **exact diff** and gets
  an **explicit human yes** before running them — never silent writes.
- The stage review (and the pin approval ceremony) shows the collection,
  each template field value, and the attribution state, so a human sees
  exactly what metadata will be pinned.
- **Attribution is on by default.** Every staged metadata carries
  `"minted_with": "XRPL-Muse"` and `"minted_with_url":
  "https://github.com/terramike/xrpl-muse-skill"` unless the minter
  passes `--no-attribution`. The pin step re-verifies the attribution
  block against the stage digest — editing it out of the staged record
  fails the mint rather than minting silently unattributed.
- **Minting for someone else's collection:** you can mint as the
  collection issuer **or** as its on-ledger authorized `NFTokenMinter`
  (`--issuer r...`). Before staging, the skill reads the issuer's
  `AccountRoot` from a **validated** ledger and proceeds only if
  `NFTokenMinter` equals your account — lookup failures, unvalidated
  data, or a mismatch refuse the mint. The proposed `NFTokenMint`
  carries the `Issuer` field (self-issued mints never do).

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
  price check, and price sanity is the human's call — but both `nft-buy`
  and `nft-bid` now append an advisory xrpl.to safety section (issuer
  scam screen, collection floor, asking × floor multiple, approx last
  sale; `--no-safety` skips).
- `top-collections [--sort vol24h|trendingScore] [--limit 10]` — ranked
  NFT collections with floor, 24h volume, owners, and 24h sales
  (read-only, "Data by xrpl.to" credit).
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

