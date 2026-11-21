# Changelog

## 0.15.0

Cleanup release. Nothing here is a new trading command.

- The locked install works on Python 3.12 and 3.13 on linux x86_64. `websockets` and `wrapt` now list both the cp312 and cp313 manylinux wheel hashes. Existing pins are unchanged.
- GitHub Actions runs the offline suite on Python 3.12 and 3.13. It does not start the network end-to-end files or `tests/test_wallet.py`, which blocks on the backup prompt.
- `farm about` and `farm links` print without opening a ledger client.
- The manual no longer documents a TrustLink checker. That command and its data file are not in this skill.
- The Clavi5 beta client is not installed by `install.sh`. It is not part of propose, approve, and sign.
- Docs match the code on signing. Fresh installs are read-only until `go live`. The propose path does not read a seed and does not submit. `xrpl-sign` signs only with `--approve` of the exact hash and refuses while read-only. Opt-in local commands can store a seed, and wallet backup or autopilot's backup ceremony can display one once.
- `SKILL.md` keeps the safety rules and links the long command, menu, NFT, giveaway, and favorites sections from `references/`.
- `install.sh` copies `references/` and `llms.txt`.
- Autonomous mode is not included in this build.

Notes for work that landed after tag v0.14.1 and was not in that release's notes:

- HOL Guard profile links in the README, the manual, and the security policy.
- Artist directory updates.
- NFT Radar across the curated artist list.
- The public `fuzzy-deals` scanner.

## 0.14.1

Security release. See the v0.14.1 section of `README.md`.
