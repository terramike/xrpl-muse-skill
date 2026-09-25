# NFT artwork + IPFS pinning (v0.6)

Minting is a deliberate **two-step** flow. `xrpl-trade nft-stage`
validates the artwork locally and writes a reviewable stage record with
**zero network calls**; `xrpl-trade nft-pin-and-propose` is the approved
action that pins and proposes. Pinning is an external write — it happens
*inside* the approved action, never before it. This page explains the
hosting model, the pipeline, and the operator's obligations.

## Bring your own Pinata account

There is no shared media host. **Every person who installs this skill uses
their own Pinata account and their own `PINATA_JWT`.** Their artwork and
metadata are pinned under their own account. The skill's publisher does not
host, pay for, or see anyone else's files.

The JWT never belongs in the repository, in a proposal, in chat output, or
in the audit log. Treat it like a seed: it is **injected for the single
pin operation only**, never exported into a shell (an `export` leaves it
in shell history and the process environment for everything after it).

```bash
# 1. stage offline — no network, no JWT needed:
xrpl-trade nft-stage --file ~/.xrpl/media/art.png --name "Neon Drift" \
    --description "Series 1, piece 3" --royalty-bps 1000
# → validates + hashes the file, writes a stage record. Review it.

# 2. the human approves pinning + proposal as ONE action; the JWT lives
#    only for this command:
PINATA_JWT="$(vault read -field=jwt secret/pinata)" \
    xrpl-trade nft-pin-and-propose --stage <stage-id>
```

On Pinata's free tier, both pins (artwork + metadata JSON) count against the
operator's own quota. No account creation happens here — the operator brings
an account they already own.

## The pin pipeline

`bin/xrpl_pin.py` does exactly three things:

1. **Validate the source.** `read_validated_source(path)` enforces: the
   file lives inside the approved media directory (`~/.xrpl/media` or
   `XRPL_NFT_MEDIA_DIR`; symlink escapes refused), opens it `O_NOFOLLOW`,
   requires a regular non-empty file under 10 MiB, sniffs the MIME from
   magic bytes (PNG/JPEG/GIF/WebP only), and SHA-256 hashes it while
   reading. Anything else is refused before a single byte leaves the
   machine.
2. **Pin the artwork** (`pinFileToIPFS`) → image CID.
3. **Pin the metadata JSON** (`pinJSONToIPFS`) in the XLS-24d shape
   (`name`, `description`, `image: ipfs://<image-cid>`) → metadata CID.

`xrpl-trade nft-pin-and-propose` re-validates the file against the **staged
SHA-256** first (a file swapped after staging is refused — no TOCTOU),
prints exactly what will leave the machine (file, hash, size, metadata),
then pins and hex-encodes `ipfs://<metadata-cid>` into the proposal's
`URI` field (policy caps it at `nft.max_uri_bytes`). The pinner only ever
sees the validated file and the exact reviewed metadata.

## CIDs are portable

The on-ledger `URI` is just an `ipfs://<cid>` string. If Pinata ever goes
away or the operator moves accounts, they re-pin the same bytes at another
provider — the CID is a content hash, so it does not change, and nothing on
the ledger needs editing. No XRPL-specific gateway URL is ever stored
on-ledger.

## Operator obligations

- **Keep the JWT out of git — and out of shells.** `xrpl_pin.py` reads
  `PINATA_JWT` from the environment only; there is no config-file path
  and no flag for it. Inject it for the single `nft-pin-and-propose`
  invocation (`PINATA_JWT="$(vault …)" xrpl-trade nft-pin-and-propose …`);
  never `export` it, never paste it into chat, never commit it.
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

## Transfers (`nft-send`)

```bash
xrpl-trade nft-send --token-id <64-hex-id> --to <favorite-name|r-address> \
    [--expires-in 86400]
```

- A **gift**, not a sale: the offer carries a 0-drops `Amount` and a
  `Destination`. The ledger has no direct NFT-transfer transaction —
  sending is a transfer offer the recipient must accept before it
  expires. Nothing moves until they do.
- `--to` resolves against the local favorites file first
  (case-insensitive), then as a classic r-address; anything else is
  refused. The resolved address is printed in the proposal, and the
  favorite name when one matched.
- Policy carve-out: a 0-XRP `NFTokenCreateOffer` is allowed **only** as a
  sell-flag offer with a `Destination` (a transfer). 0-XRP offers with no
  destination, and 0-amount buy offers, are still refused. The signer
  ceremony describes it as `TRANSFER (gift — 0 XRP, NOT a sale)`; it
  spends 0 XRP beyond the fee.
- The recipient accepts with `nft-buy --offer-index <idx>` (the
  `nft.allow_buy_offers` toggle gates all `NFTokenAcceptOffer`s).
