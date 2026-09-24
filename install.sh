#!/bin/bash
# Install the XRPL trading skill into this Muse workspace.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/workspace/skills/xrpl"
mkdir -p "$DEST"
cp -r "$SRC/SKILL.md" "$SRC/README.md" "$SRC/requirements.txt" "$SRC/bin" "$DEST/"
pip install -r "$DEST/requirements.txt"
echo ""
echo "Installed to $DEST"
echo "Next: run  $DEST/bin/xrpl-trade setup   (start with testnet)"
echo "Or tell your Muse: 'set up my XRPL wallet on testnet'"
