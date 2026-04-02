#!/usr/bin/env bash
set -euo pipefail

IMAGE_REPO="${1:-crpi-iihofxt94xlrdrvd.cn-shanghai.personal.cr.aliyuncs.com/lazyops/lazyopsatest}"
IMAGE_TAG="${2:-cli-$(date +%Y%m%d%H%M%S)}"
PLATFORM="${PLATFORM:-linux/amd64}"
DOCKERFILE="${DOCKERFILE:-Dockerfile.cli}"
IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

if [[ ! -f "$DOCKERFILE" ]]; then
  echo "dockerfile not found: $DOCKERFILE"
  exit 1
fi

echo "==> building and pushing CLI image: $IMAGE"
docker buildx build --platform "$PLATFORM" -f "$DOCKERFILE" -t "$IMAGE" --push .

echo "==> done: $IMAGE"
