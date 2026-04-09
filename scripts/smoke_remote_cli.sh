#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <user@host>"
  echo "Example: $0 root@192.168.10.101"
  exit 1
fi

TARGET="$1"

echo "==> remote CLI smoke: ${TARGET}"
ssh "$TARGET" 'bash -s' <<'REMOTE'
set -euo pipefail

pass() { echo "[PASS] $*"; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

command -v lazysre >/dev/null 2>&1 || fail "lazysre command not found"
pass "lazysre found: $(command -v lazysre)"

lazysre --help >/dev/null
pass "lazysre --help"

lazysre install-doctor >/dev/null
pass "lazysre install-doctor"

lazysre --provider mock "列出 docker service" >/tmp/lazysre-smoke-mock.txt
grep -Eq "mock|docker|工具|dry-run" /tmp/lazysre-smoke-mock.txt || {
  cat /tmp/lazysre-smoke-mock.txt
  fail "mock docker natural-language smoke did not produce expected output"
}
pass "natural-language mock docker path"

if command -v docker >/dev/null 2>&1; then
  docker version >/dev/null
  pass "docker version"
  if docker info --format "{{.Swarm.LocalNodeState}}" 2>/dev/null | grep -qi active; then
    docker service ls >/dev/null
    pass "docker swarm service ls"
  else
    echo "[WARN] Docker is installed but swarm is not active"
  fi
else
  echo "[WARN] docker command not found"
fi

echo "==> remote CLI smoke completed"
REMOTE
