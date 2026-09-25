# NFT artwork + IPFS pinning (v0.5)

`xrpl-trade nft-mint` pins artwork to IPFS through Pinata, then mints an
`NFTokenMint` whose `URI` points at the pinned metadata. This page explains
the hosting model, the pinning pipeline, and the operator's obligations.

## Bring your own Pinata account

There is no shared media host. **Every person who installs this skill uses
their own Pinata account and their own `PINATA_JWT`.** Their artwork and
metadata are pinned under their own account. The skill's publisher does not
host, pay for, or see anyone else's files.

The JWT never belongs in the repository, in a proposal, in chat output, or
in the audit log. Treat it like a seed: the vault injects it into the
environment at pin time, and only the pinner's environment holds it.

```bash
export PINATA_JWT="eyJhbGciOi..."
xrpl-trade nft-mint --file art.png --name "Neon Drift" \
    --description "Series 1, piece 3" --royalty-bps 1000
```

On Pinata's free tier, both pins (artwork + metadata JSON) count against the
operator's own quota. No account creation happens here — the operator brings
an account they already own.

## The pin pipeline

`bin/xrpl_pin.py` does exactly three things:

1. **Pin the artwork.** `pin_artwork(path)` uploads the file bytes and
   returns the image CID (`pinFileToIPFS`).
2. **Build metadata** in the XLS-24d shape:
   ```json
   {
     "name": "Neon Drift",
     "description": "Series 1, piece 3",
     "image": "ipfs://<image-cid>"
   }
   ```
3. **Pin the metadata JSON** (`pinJSONToIPFS`) and return its CID.

`xrpl-trade nft-mint` then hex-encodes `ipfs://<metadata-cid>` and writes it
into the proposal's `URI` field (policy caps it at 256 bytes, see below).
Pinning happens **before** the proposal is built, so a failed pin can never
produce a mint pointing at nothing.

## CIDs are portable

The on-ledger `URI` is just an `ipfs://<cid>` string. If Pinata ever goes
away or the operator moves accounts, they re-pin the same bytes at another
provider — the CID is a content hash, so it does not change, and nothing on
the ledger needs editing. No XRPL-specific gateway URL is ever stored
on-ledger.

## Operator obligations

- **Keep the JWT out of git.** `xrpl_pin.py` reads `PINATA_JWT` from the
  environment only; there is no config-file path and no flag for it.
- **Keep pins alive.** NFTs reference content by CID, but content only
  resolves while *someone* pins it. If the operator deletes the Pinata
  account, the NFT's `URI` keeps working on-ledger but wallets and
  marketplaces can no longer show the art.
- **Royalty is immutable.** `--royalty-bps` (0–5000, default 1000 = 10%)
  becomes the ledger `TransferFee` (bps × 10). The minter must be the
  issuer for it to apply, and it can never be changed or removed after
  the mint — double-check the number before approving the proposal.

## Listings (`nft-list`)

```bash
xrpl-trade nft-list --token-id <64-hex-id> --price-xrp 25 \
    [--destination r...] [--expires-in 86400]
```

- Sell offers only (`tfSellNFToken` is mandatory; buy offers are
  unrepresentable — the schema refuses an `Owner` field).
- XRP-denominated only in v1; IOU prices are denied by policy.
- Every listing gets a ledger `Expiration` (default 24h, capped by
  `max_offer_lifetime_seconds`).
- `--destination` makes it a private sale to one buyer address; without it
  anyone can accept.
