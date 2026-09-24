# XRPL Trading Skill for Muse

Trade on the XRP Ledger from your terminal, with your Muse as co-pilot:
check XRP and token balances, view RLUSD/XRP order books, manage
trustlines, place and cancel offers, send payments. Built on the official
[`xrpl-py`](https://github.com/XRPLF/xrpl-py) library.

## Safety first

- **Read-only commands** (`balance`, `quote`, `offers`) run freely.
- **Every write** (`trustline`, `buy`, `sell`, `cancel`, `send`) needs your
  explicit approval in the moment — side, amount, price/total, network —
  before anything is submitted. A general "go trade" never covers a
  specific order.
- **Start on testnet.** Only move to mainnet deliberately, with a
  **dedicated, limited-funds wallet** — never your main holdings.
- Your seed is typed hidden, verified against your address, and stored at
  `~/.xrpl/config.json` with mode `0600`. It never appears in chat, logs,
  or shared files. Back it up yourself (password manager) — nobody else
  can recover it for you.
- `--dry-run` prints the exact transaction JSON without submitting
  anything. Use it for previews.

## Install

```bash
git clone https://github.com/terramike/xrpl-muse-skill.git ~/workspace/skills/xrpl
pip install -r ~/workspace/skills/xrpl/requirements.txt
```

Then tell your Muse: *"set up my XRPL wallet on testnet"* — or run it
yourself:

```bash
~/workspace/skills/xrpl/bin/xrpl-trade setup
```

## Testnet walkthrough (do this first)

```bash
bin/xrpl-trade faucet            # fresh testnet wallet + test XRP (prints seed once — save it)
bin/xrpl-trade setup             # choose testnet, paste address + seed
bin/xrpl-trade balance           # check it
bin/xrpl-trade quote             # live RLUSD/XRP order book
bin/xrpl-trade --dry-run buy --amount 10 --price 1.50   # preview only, submits nothing
```

## Mainnet

When you're ready — and only with a dedicated limited-funds wallet:

```bash
bin/xrpl-trade setup             # choose mainnet this time
bin/xrpl-trade --network mainnet balance
bin/xrpl-trade --network mainnet trustline --currency RLUSD   # needs your approval each run
bin/xrpl-trade --network mainnet buy --amount 10 --price 1.50 # needs your approval each run
```

Global flags go before the subcommand: `--network mainnet`,
`--dry-run`.

## Commands

| Command | What it does |
|---|---|
| `setup` | Interactive wallet setup (hidden seed prompt, verifies seed ↔ address) |
| `balance [address]` | XRP + trustline balances |
| `quote [--issuer ADDR] [--limit N]` | Top-of-book RLUSD/XRP bids & asks |
| `trustline --currency RLUSD [--issuer ADDR] [--limit N]` | Create/adjust a trustline (TrustSet) |
| `buy --amount <XRP> --price <RLUSD/XRP>` | Buy XRP with RLUSD at a limit price |
| `sell --amount <XRP> --price <RLUSD/XRP>` | Sell XRP for RLUSD at a limit price |
| `offers [address]` | Open offers with sequence numbers |
| `cancel --seq N` | Cancel an open offer |
| `send --to <addr> --amount <n> [--ccy XRP]` | Send XRP or an IOU |
| `faucet` | Fund a fresh testnet/devnet wallet |

RLUSD issuer default: `rMxCKbEDwqr76QuheSUMdEGf4B9xJ8m5De`.

## Companion dashboard

A read-only web dashboard (live order book, wallet panel, trade-ticket
previews that copy exact CLI commands): it pairs with this skill and
needs no backend. Host the single HTML file anywhere static.

## License

MIT — do your own diligence; trading real assets carries real risk.
