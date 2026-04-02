#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
OUT_DIR="${OUT_DIR:-dist}"

echo "==> building lsre wheel/sdist"
"$PYTHON_BIN" -m pip install --upgrade build
"$PYTHON_BIN" -m build --outdir "$OUT_DIR"

echo "==> artifacts"
ls -lh "$OUT_DIR"

echo "==> done"
