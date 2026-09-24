#!/bin/bash
# Install the XRPL trading skill into this Muse workspace.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/workspace/skills/xrpl"
mkdir -p "$DEST"
cp -r "$SRC/SKILL.md" "$SRC/README.md" "$SRC/SECURITY.md" \
      "$SRC/requirements.txt" "$SRC/requirements-locked.txt" \
      "$SRC/approved.example.json" \
      "$SRC/policy.example.json" "$SRC/bin" "$SRC/tests" "$DEST/"
pip install -r "$DEST/requirements.txt"
echo ""
echo "Installed to $DEST"
echo "Next: run  $DEST/bin/xrpl-trade setup   (start with testnet)"
echo "Then:      $DEST/bin/xrpl-sign init-policy"
echo "Or tell your Muse: 'set up my XRPL wallet on testnet'"
