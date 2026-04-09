#!/usr/bin/env bash
set -euo pipefail

# Install lazysre for end users with either pipx (preferred) or a local venv fallback.
SOURCE="${LAZYSRE_PIP_SOURCE:-${1:-git+https://github.com/not1ie/lazysre.git}}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
INSTALL_ROOT="${LAZYSRE_HOME:-$HOME/.lazysre}"
BIN_DIR="${HOME}/.local/bin"
PIP_INDEX_URL_VALUE="${LAZYSRE_PIP_INDEX_URL:-${PIP_INDEX_URL:-https://mirrors.aliyun.com/pypi/simple/}}"
PIP_EXTRA_INDEX_URL_VALUE="${LAZYSRE_PIP_EXTRA_INDEX_URL:-${PIP_EXTRA_INDEX_URL:-}}"
PIP_TRUSTED_HOST_VALUE="${LAZYSRE_PIP_TRUSTED_HOST:-${PIP_TRUSTED_HOST:-mirrors.aliyun.com}}"

echo "[lazysre] source: ${SOURCE}"
echo "[lazysre] pip index: ${PIP_INDEX_URL_VALUE:-default}"

PIP_ARGS=()
if [[ -n "${PIP_INDEX_URL_VALUE}" ]]; then
  PIP_ARGS+=("-i" "${PIP_INDEX_URL_VALUE}")
fi
if [[ -n "${PIP_EXTRA_INDEX_URL_VALUE}" ]]; then
  PIP_ARGS+=("--extra-index-url" "${PIP_EXTRA_INDEX_URL_VALUE}")
fi
if [[ -n "${PIP_TRUSTED_HOST_VALUE}" ]]; then
  IFS=',' read -ra TRUSTED_HOSTS <<< "${PIP_TRUSTED_HOST_VALUE}"
  for host in "${TRUSTED_HOSTS[@]}"; do
    host="$(echo "$host" | xargs)"
    if [[ -n "$host" ]]; then
      PIP_ARGS+=("--trusted-host" "$host")
    fi
  done
fi

if command -v pipx >/dev/null 2>&1; then
  echo "[lazysre] pipx detected, installing with pipx..."
  if [[ ${#PIP_ARGS[@]} -gt 0 ]]; then
    pipx install --force "${SOURCE}" --pip-args "${PIP_ARGS[*]}"
  else
    pipx install --force "${SOURCE}"
  fi
  echo "[lazysre] done. run: lazysre"
  exit 0
fi

echo "[lazysre] pipx not found, using virtualenv fallback..."
"${PYTHON_BIN}" -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/pip" install "${PIP_ARGS[@]}" --upgrade pip
"${INSTALL_ROOT}/venv/bin/pip" install "${PIP_ARGS[@]}" "${SOURCE}"

mkdir -p "${BIN_DIR}"
ln -sf "${INSTALL_ROOT}/venv/bin/lazysre" "${BIN_DIR}/lazysre"
ln -sf "${INSTALL_ROOT}/venv/bin/lsre" "${BIN_DIR}/lsre"

echo "[lazysre] installed to ${INSTALL_ROOT}/venv"
if [[ ":$PATH:" != *":${BIN_DIR}:"* ]]; then
  echo "[lazysre] add this to your shell profile (~/.zshrc or ~/.bashrc):"
  echo "export PATH=\"${BIN_DIR}:\$PATH\""
fi
echo "[lazysre] done. run: lazysre"
