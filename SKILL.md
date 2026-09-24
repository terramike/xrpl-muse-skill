---
name: xrpl
description: Trade on the XRP Ledger from the terminal: check XRP and token balances, view RLUSD/XRP order books, manage trustlines, place and cancel offers, send payments. Built on the official xrpl-py library. Use when the user wants anything done on the XRPL — prices, balances, buying or selling XRP.
---

# XRPL Trading

## Purpose
Do real things on the XRP Ledger: balances, order books, trustlines, offers (place/cancel), payments. Read-only commands run freely; every write needs the user's explicit in-the-moment approval with exact terms.

## Tooling
CLI: `bin/xrpl-trade` (Python, needs `pip install -r requirements.txt`).

- `setup` — interactive wallet setup. Seed typed hidden, stored at `~/.xrpl/config.json` mode 0600. Verifies the seed matches the address before saving.
- `balance [address]` — XRP + trustline balances.
- `quote --base XRP --quote RLUSD [--issuer ADDR] [--limit N]` — top-of-book bids/asks.
- `trustline --currency RLUSD [--issuer ADDR] [--limit N]` — TrustSet.
- `buy --amount <XRP> --price <RLUSD/XRP>` / `sell --amount <XRP> --price <RLUSD/XRP>` — OfferCreate.
- `offers [address]` — list open offers with sequence numbers.
- `cancel --seq N` — OfferCancel.
- `send --to <addr> --amount <n> [--ccy XRP]` — Payment.
- `faucet [--network testnet|devnet]` — fund a fresh test wallet (prints the seed once).

Global flags: `--network mainnet|testnet|devnet` (default: configured, else testnet), `--dry-run` (print the exact transaction JSON, submit nothing).

Networks: mainnet `s1.ripple.com` (fallback `s2`), testnet `s.altnet.rippletest.net`, devnet `s.devnet.rippletest.net`.
RLUSD issuer default: `rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De` (Ripple's RLUSD issuer on mainnet).

## Auth
The wallet seed lives in `~/.xrpl/config.json` (0600) or the `XRPL_SEED` env var. The Secure Vault has no raw-seed flow, so `setup` + hidden prompt is the path — the seed never appears in chat, logs, memory, or files outside that config.

## Operating Rules
1. Read-only (`balance`, `quote`, `offers`) runs freely. Writes (`trustline`, `buy`, `sell`, `cancel`, `send`) need the user's explicit approval in the moment: state side, amount, price, total, and network, then wait for yes. A general "go trade" never covers a specific order.
2. Default network is testnet until the user runs `setup` for mainnet. Never switch networks silently — always name the network in the approval.
3. New wallet? Start on testnet: `faucet`, then `setup`. Only move to mainnet on the user's word, with a dedicated limited-funds wallet.
4. Prefer `--dry-run` when the user wants a preview; show the JSON, then ask.
5. Never print, log, or repeat the seed. Never invent the RLUSD issuer or a price — `quote` is the source of truth.
6. This skill does discrete, user-approved trades — not continuous market-making.
