# xrpl-muse-skill v0.5

Trade the XRP Ledger from the terminal — any token pair — with a hard safety
boundary between **proposing** a trade and **signing** it. v0.5 adds NFT
minting and XRP-denominated listings under the same propose → approve →
sign boundary.

Built for AI agents (Muse, Grok, OpenClaw-style bots — anything with a
terminal). **Testnet-safe by default; mainnet requires the Muse vault
signer or an external protected signer with real per-transaction human
approval.** A same-user local install is testnet-only — see
`SECURITY.md` "Deployment profiles" before mainnet.

## The idea

Most trading tools ask the agent to "ask the human first" and hope it does.
This skill splits the job in two:

- **`xrpl-trade`** builds the transaction, autofills it against the live
  network, shows you *everything* (account, network, assets + issuers,
  amounts, limit price, max spend, fee, expiry), seals it in a **hash-bound
  proposal envelope**, and stops. It never sees your seed. It cannot submit.
- **`xrpl-sign`** is the only program that touches the seed (from the
  `XRPL_SEED` env var — never from a config file). It re-verifies the
  envelope, derives the summary from the transaction itself (nothing stored
  is trusted), enforces the policy file, and signs **only** with explicit
  human `--approve` of that exact hash.

```bash
xrpl-trade buy --pair ARMY/XRP --amount 1000 --price 0.005
# → full proposal + hash. Nothing submitted.

xrpl-sign --hash a2c72140d080ca0f --approve
# → envelope verify → policy checks → sign → persist → validated result
```

## What v0.5 adds

- **NFT minting** (`xrpl-trade nft-stage`, then `nft-pin-and-propose`):
  a deliberate two-step flow. `nft-stage` validates the artwork locally
  (approved media directory, size and image-type checks, SHA-256) and
  writes a reviewable stage record with **zero network calls**.
  `nft-pin-and-propose` is the approved action: it re-validates the file
  against the staged hash, pins artwork + XLS-24d metadata to IPFS
  through the operator's **own** Pinata account, then proposes an
  `NFTokenMint` whose `URI` points at the metadata CID. Pinning is an
  external write and happens *inside* the approved action — never before
  it. `PINATA_JWT` is injected for the single operation (never exported
  into a shell, never stored); the publisher hosts no one's media.
- **XRP listings** (`xrpl-trade nft-list`): proposes XRP-denominated
  *sell* offers only. IOU prices are denied, every listing carries a
  ledger expiration.
- **NFT inventory** (`xrpl-trade nft-inventory`): read-only listing of
  every NFToken an account owns, with decoded URIs, flags, and issuers.
  Accepts a favorite name as well as an r-address.
- **NFT buying** (`xrpl-trade nft-buy --offer-index …`): verifies the
  sell offer **from the ledger** (sell offer only — buy offers and IOU
  prices refused), shows the on-ledger seller, URI, and taxon before
  proposing `NFTokenAcceptOffer`. The signer re-verifies the offer at
  signing time; a changed or vanished offer is refused. The skill reports
  on-ledger facts and never calls a token "authentic" — anyone can mint
  the same artwork, so the human verifies the ISSUER is the minter
  they expect (the seller is only the current owner). Buying spends XRP immediately and runs through the
  per-transaction and rolling-24h spend caps.
- **NFT bids** (`xrpl-trade nft-bid --token-id … --seller r… --price-xrp …`):
  proposes a buy-side offer; the bid XRP locks until the offer is
  accepted, cancelled, or expires. The buy side is opt-in
  (`nft.allow_buy_offers`, default off) with a per-bid cap
  (`nft.max_bid_xrp`).
- **NFT transfers** (`xrpl-trade nft-send --token-id … --to <favorite|r…>`):
  proposes a 0-XRP *transfer offer* (a gift, not a sale) to a favorite
  name or r-address. The recipient must accept before it expires; it
  spends 0 XRP beyond the fee, and the signer ceremony describes it as a
  transfer, never a sale.
- **NFT policy gates**: royalty (`TransferFee`) capped per policy and
  immutable after mint, burnable/transferable flag allowlist, URI
  byte-length cap, rolling-24h mint count, and a conservative v4 policy
  migration that never widens `allowed_tx_types` on its own. No
  order-book price check for NFTs: each token is one-of-one, so price
  sanity stays the human's decision.
- **Artist watchlist** (`xrpl-trade favorites`, `xrpl-trade nft-new`):
  entirely read-only — a local named watchlist of artist wallets plus a
  watermarked "what's new" digest showing new mints, listing prices, and
  xrp.cafe links. No proposals, no signing, no approvals involved.
- **XRPresso discovery** (`xrpl-trade xrpresso …`): read-only search of
  the XRPresso P2P marketplace (listings, NFTs, auctions, stats) via its
  free anonymous Discovery API — no key, no signup. The agent finds,
  the human buys: every result prints its XRPresso deep link
  (`?ref=api_v1` preserved) to open in their UI and sign in your own
  wallet. Links are validated (https on xrpresso.io only — anything
  else is withheld, never printed), calls are throttled well under the
  platform's rate limit, and the feature touches no policy, no
  `~/.xrpl`, and no ledger. Honest limits: small early-stage catalog,
  marketplace not a trading venue (no swap endpoints).

## What v0.3 hardens

- **Hash-bound envelope** (`xrpl-proposal/3`): the approval hash covers the
  network, account, action, creation time, policy version, and the canonical
  XRPL binary of the complete transaction. Tampering with any of it —
  including the proposal file — voids the approval.
- **Strict transaction schemas**: only `OfferCreate`, `OfferCancel`,
  `TrustSet`, `Payment` are signable, and every field is allowlisted per
  type. No smuggled `Paths`, `SendMax`, memos, or partial-payment flags.
- **Derived, never stored**: pair, side, amounts, and price are computed
  from the transaction inside the signer.
- **Per-asset spend limits**: per-transaction and rolling-24h caps per asset,
  reserved atomically. Assets with no configured limit are blocked.
- **Exact-pair enforcement**: offers must match an approved pair exactly —
  unlisted token/token combinations are denied.
- **Destination policy**: payments only to allowlisted `(address,
  destination_tag)` pairs; conflicting X-address/CLI tags rejected;
  `RequireDestTag` destinations refuse untagged payments.
- **Crash-safe submission**: sign → persist the signed hash and
  `LastLedgerSequence` → submit → wait for the validated ledger result.

## Why the allowlist matters

Tickers mean nothing on the XRP Ledger — anyone can mint a fake "ARMY".
This skill trades **pair names mapped to vetted issuer addresses**, and the
signer extracts token identities from the transaction JSON itself, so raw
issuer arguments can't bypass it.

Live at launch: `XRP/RLUSD, BTC/XRP, XLM/XRP, ARMY/XRP, PHNIX/XRP, BCHAMP/XRP,
FUZZY/XRP`

The shipped `approved.example.json` contains two template pairs
(`XRP/RLUSD`, `ARMY/XRP`) — copy it to `~/.xrpl/approved.json` and add
only pairs whose issuers you have personally vetted. Tickers mean nothing
on XRPL; the issuer address is the identity.

## Install

```bash
pip install -r requirements-locked.txt   # hash-pinned dependencies
xrpl-trade setup            # address + network (never the seed)
xrpl-sign init-policy       # policy file v4, testnet-locked by default
```

The signer reads the seed **only** from `XRPL_SEED`, provided by your secret
manager or agent vault after human approval. Testnet funds:
`xrpl-trade faucet --network testnet`

## What it does

- **Read:** balances, order books for any pair, open offers, issuer risk
  inspection (domain, transfer fees, freeze flags), trade planning
  (estimated fill, price impact, max spend), transaction reconciliation,
  NFT inventory per account.
- **Write (all gated):** limit buys/sells, trustlines, offer cancels, payments
  with destination-tag and X-address support, NFT mints, NFT listings,
  NFT buys (sell-offer acceptance), and NFT bids.

## Security

See [SECURITY.md](SECURITY.md) — including the platform boundary: `--approve`
is an assertion, not evidence of human approval, and the advisory that
versions before commit `c3273e59` shipped inverted buy/sell and must not be
used for trading.

## Deployment profiles

**1. Muse vault signer (supported for mainnet).** The signer runs under
Muse with the seed injected per-operation from the vault, only after
genuine per-transaction human approval. This is the only mainnet posture
the publisher supports.

**2. Xaman-human (community path).** A human reviews and signs in Xaman
(or another external wallet); the skill prepares proposals but never
touches a seed. A dedicated signer adapter is parked for later — today
this means the human signs outside the skill.

**3. Autonomous-experimental (testnet only).** A same-user local agent
running the signer itself. Convenient, but the security boundary does
**not** hold here: a same-UID process can read the signer's environment
and rewrite its policy and state files, and `0600` permissions do not
stop it. Use testnet, or accept explicitly that you are your own
adversary.

### What the NFT checks do and don't cover

The buy ceremony verifies on-ledger facts: the offer is a sell offer,
the seller owns the token, the issuer (minter) is the artist you expect,
the URI/taxon match. It does **not** protect market value (no
floor-price or rarity check — price sanity is the human's call) and it
does **not** prove ownership of the underlying art (anyone can mint the
same bytes). Token/issuer allowlists and floor-price guardrails are
parked as opt-in policy features, not built.

## Tests

```bash
python3 tests/test_v04.py          # 78 adversarial logic tests, no network
python3 tests/test_nft.py          # 104 NFT adversarial tests, no network
python3 tests/test_favorites.py    # 67 favorites + nft-new tests, no network
python3 tests/test_e2e_testnet.py  # 52 end-to-end checks on testnet,
                                   # fully isolated in a temporary HOME —
                                   # never touches the operator's real ~/.xrpl
```

## License

MIT — see [LICENSE](LICENSE).
