#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <user@host> [stack_file] [stack_name]"
  exit 1
fi

TARGET="$1"
STACK_FILE="${2:-deploy/swarm/lazysre-stack.yml}"
STACK_NAME="${3:-lazysre}"
REMOTE_FILE="/tmp/${STACK_NAME}-stack.yml"

scp "$STACK_FILE" "$TARGET:$REMOTE_FILE"
ssh "$TARGET" "docker stack deploy -c $REMOTE_FILE $STACK_NAME && docker service ls | grep $STACK_NAME"

