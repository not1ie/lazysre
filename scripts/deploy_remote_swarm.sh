#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <user@host> [stack_file] [stack_name] [image_tag]"
  exit 1
fi

TARGET="$1"
STACK_FILE="${2:-deploy/swarm/lazysre-stack.yml}"
STACK_NAME="${3:-lazysre}"
IMAGE_TAG="${4:-$(date +%Y%m%d%H%M%S)}"
REMOTE_FILE="/tmp/${STACK_NAME}-stack.yml"
REMOTE_SRC="/tmp/${STACK_NAME}-src-${IMAGE_TAG}"
REMOTE_IMAGE="${STACK_NAME}:${IMAGE_TAG}"

if [[ ! -f "$STACK_FILE" ]]; then
  echo "stack file not found: $STACK_FILE"
  exit 1
fi

echo "==> packaging source"
tar -czf - \
  --exclude=.git \
  --exclude=.venv \
  --exclude=.pytest_cache \
  --exclude=.data \
  --exclude='*.pyc' \
  --exclude='__pycache__' \
  . | ssh "$TARGET" "rm -rf '$REMOTE_SRC' && mkdir -p '$REMOTE_SRC' && tar -xzf - -C '$REMOTE_SRC'"

echo "==> uploading stack file"
scp "$STACK_FILE" "$TARGET:$REMOTE_FILE"

echo "==> building image on remote: $REMOTE_IMAGE"
ssh "$TARGET" "docker build -t '$REMOTE_IMAGE' '$REMOTE_SRC'"

echo "==> deploying stack"
ssh "$TARGET" "LAZYSRE_IMAGE='$REMOTE_IMAGE' docker stack deploy -c '$REMOTE_FILE' '$STACK_NAME' && docker service ls | grep '$STACK_NAME'"

echo "==> done: $REMOTE_IMAGE"
