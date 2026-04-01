#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <user@host> [manifest]"
  exit 1
fi

TARGET="$1"
MANIFEST="${2:-deploy/k8s/lazysre.yaml}"
REMOTE_PATH="/tmp/lazysre.yaml"

scp "$MANIFEST" "$TARGET:$REMOTE_PATH"
ssh "$TARGET" "kubectl apply -f $REMOTE_PATH && kubectl -n lazysre rollout status deploy/lazysre --timeout=300s && kubectl -n lazysre get pod,svc -o wide"

