#!/usr/bin/env bash
set -euo pipefail

# Preflight checks for npm release readiness.
# Usage:
#   ./scripts/check_npm_release.sh
#   ./scripts/check_npm_release.sh 0.1.1

TARGET_VERSION="${1:-}"
FAILS=0
WARNS=0

# Keep npm diagnostics inside the repository so preflight also works in
# sandboxed shells and CI runners with restricted home directories.
export npm_config_cache="${npm_config_cache:-${PWD}/.data/npm-cache}"
export npm_config_logs_dir="${npm_config_logs_dir:-${PWD}/.data/npm-logs}"
mkdir -p "${npm_config_cache}" "${npm_config_logs_dir}"

pass() {
  echo "[PASS] $*"
}

warn() {
  echo "[WARN] $*"
  WARNS=$((WARNS + 1))
}

fail() {
  echo "[FAIL] $*"
  FAILS=$((FAILS + 1))
}

if [[ ! -f package.json ]]; then
  fail "package.json not found (run from repository root)."
fi

if ! command -v git >/dev/null 2>&1; then
  fail "git is required."
else
  pass "git found"
fi

if ! command -v node >/dev/null 2>&1; then
  fail "node is required (>=18)."
else
  NODE_VER="$(node -v || true)"
  pass "node found ${NODE_VER}"
fi

if ! command -v npm >/dev/null 2>&1; then
  fail "npm is required."
else
  NPM_VER="$(npm -v || true)"
  pass "npm found ${NPM_VER}"
fi

if [[ ${FAILS} -eq 0 ]]; then
  PKG_NAME="$(npm pkg get name | tr -d '\"')"
  PKG_VERSION="$(npm pkg get version | tr -d '\"')"
  if [[ -z "${PKG_NAME}" || "${PKG_NAME}" == "null" ]]; then
    fail "package name is empty in package.json."
  else
    pass "package name=${PKG_NAME}"
  fi
  if [[ ! "${PKG_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
    fail "package version is not semver: ${PKG_VERSION}"
  else
    pass "package version=${PKG_VERSION}"
  fi

  if [[ -n "${TARGET_VERSION}" ]]; then
    if [[ "${PKG_VERSION}" != "${TARGET_VERSION}" ]]; then
      warn "target version (${TARGET_VERSION}) differs from package.json (${PKG_VERSION}); release script will update it."
    else
      pass "target version matches package.json"
    fi
  fi

  if [[ -f "pyproject.toml" ]]; then
    PYPROJECT_VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -n 1)"
    if [[ "${PYPROJECT_VERSION}" == "${PKG_VERSION}" ]]; then
      pass "pyproject version matches package.json"
    else
      fail "pyproject version (${PYPROJECT_VERSION:-missing}) differs from package.json (${PKG_VERSION})"
    fi
  else
    fail "pyproject.toml not found."
  fi

  if [[ -f "src/lazysre/__init__.py" ]]; then
    PY_INIT_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/lazysre/__init__.py | head -n 1)"
    if [[ "${PY_INIT_VERSION}" == "${PKG_VERSION}" ]]; then
      pass "python __version__ matches package.json"
    else
      fail "python __version__ (${PY_INIT_VERSION:-missing}) differs from package.json (${PKG_VERSION})"
    fi
  else
    fail "src/lazysre/__init__.py not found."
  fi
fi

if [[ -f "bin/lazysre.js" ]]; then
  pass "bin/lazysre.js exists"
else
  fail "bin/lazysre.js not found."
fi

if [[ ${FAILS} -eq 0 ]]; then
  if npm pack --dry-run >/dev/null 2>&1; then
    pass "npm pack --dry-run succeeded"
  else
    fail "npm pack --dry-run failed."
  fi
fi

if [[ ${FAILS} -eq 0 ]]; then
  if npm whoami >/dev/null 2>&1; then
    pass "npm auth is valid for current shell (npm whoami)"
  else
    warn "npm whoami failed in current shell (ok if you publish only via GitHub Actions)."
  fi
fi

if command -v gh >/dev/null 2>&1; then
  if gh auth status >/dev/null 2>&1; then
    REPO_SLUG="$(git config --get remote.origin.url | sed -E 's#(git@github.com:|https://github.com/)##; s#\\.git$##')"
    if [[ -n "${REPO_SLUG}" ]]; then
      if gh secret list -R "${REPO_SLUG}" 2>/dev/null | rg -q '^NPM_TOKEN\s'; then
        pass "GitHub secret NPM_TOKEN exists in ${REPO_SLUG}"
      else
        warn "GitHub secret NPM_TOKEN not found in ${REPO_SLUG}"
      fi
    else
      warn "unable to infer repo slug from remote.origin.url"
    fi
  else
    warn "gh installed but not authenticated; skip checking NPM_TOKEN secret."
  fi
else
  warn "gh CLI not found; skip checking GitHub secret NPM_TOKEN."
fi

echo "----"
echo "Summary: fails=${FAILS} warns=${WARNS}"
if [[ ${FAILS} -ne 0 ]]; then
  exit 1
fi
