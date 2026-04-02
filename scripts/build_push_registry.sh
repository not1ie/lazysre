#!/usr/bin/env bash
set -euo pipefail

IMAGE_REPO="${1:-crpi-iihofxt94xlrdrvd.cn-shanghai.personal.cr.aliyuncs.com/lazyops/lazyopsatest}"
IMAGE_TAG="${2:-$(date +%Y%m%d%H%M%S)}"
PLATFORM="${PLATFORM:-linux/amd64}"
IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

echo "==> building and pushing: $IMAGE"
docker buildx build --platform "$PLATFORM" -t "$IMAGE" --push .

echo "==> done: $IMAGE"
