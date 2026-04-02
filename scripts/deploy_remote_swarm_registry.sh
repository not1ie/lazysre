#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <user@host> <image_ref> [stack_file] [stack_name]"
  echo "Example: $0 root@192.168.10.101 crpi-xxx.cn-shanghai.personal.cr.aliyuncs.com/lazyops/lazyopsatest:20260402120000"
  exit 1
fi

TARGET="$1"
IMAGE_REF="$2"
STACK_FILE="${3:-deploy/swarm/lazysre-stack.yml}"
STACK_NAME="${4:-lazysre}"
REMOTE_FILE="/tmp/${STACK_NAME}-stack.yml"

if [[ ! -f "$STACK_FILE" ]]; then
  echo "stack file not found: $STACK_FILE"
  exit 1
fi

echo "==> uploading stack file"
scp "$STACK_FILE" "$TARGET:$REMOTE_FILE"

echo "==> pulling image on remote: $IMAGE_REF"
ssh "$TARGET" "docker pull '$IMAGE_REF'"

echo "==> deploying stack with registry image"
ssh "$TARGET" "LAZYSRE_IMAGE='$IMAGE_REF' docker stack deploy -c '$REMOTE_FILE' '$STACK_NAME' && docker service ls | grep '$STACK_NAME'"

echo "==> done: $IMAGE_REF"
