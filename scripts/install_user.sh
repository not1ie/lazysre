#!/usr/bin/env bash
set -euo pipefail

# Install lazysre for end users with either pipx (preferred) or a local venv fallback.
SOURCE="${1:-git+https://github.com/not1ie/lazysre.git}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_ROOT="${LAZYSRE_HOME:-$HOME/.lazysre}"
BIN_DIR="${HOME}/.local/bin"

echo "[lazysre] source: ${SOURCE}"

if command -v pipx >/dev/null 2>&1; then
  echo "[lazysre] pipx detected, installing with pipx..."
  pipx install --force "${SOURCE}"
  echo "[lazysre] done. run: lazysre"
  exit 0
fi

echo "[lazysre] pipx not found, using virtualenv fallback..."
"${PYTHON_BIN}" -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/pip" install --upgrade pip
"${INSTALL_ROOT}/venv/bin/pip" install "${SOURCE}"

mkdir -p "${BIN_DIR}"
ln -sf "${INSTALL_ROOT}/venv/bin/lazysre" "${BIN_DIR}/lazysre"
ln -sf "${INSTALL_ROOT}/venv/bin/lsre" "${BIN_DIR}/lsre"

echo "[lazysre] installed to ${INSTALL_ROOT}/venv"
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
  echo "[lazysre] add this to your shell profile (~/.zshrc or ~/.bashrc):"
  echo "export PATH=\"${BIN_DIR}:\$PATH\""
fi
echo "[lazysre] done. run: lazysre"
