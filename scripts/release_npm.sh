#!/usr/bin/env bash
set -euo pipefail

# Release npm package by version + git tag:
#   ./scripts/release_npm.sh 0.1.1
#
# The GitHub Actions workflow publishes tags in format npm-vX.Y.Z.

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <version>"
  exit 1
fi

VERSION="$1"
if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid version: ${VERSION}"
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required."
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required."
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash changes first."
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
TAG="npm-v${VERSION}"

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
  echo "Tag already exists: ${TAG}"
  exit 1
fi

CURRENT_VERSION="$(npm pkg get version | tr -d '\"')"
if [[ "${CURRENT_VERSION}" != "${VERSION}" ]]; then
  npm version "${VERSION}" --no-git-tag-version
  git add package.json
  git commit -m "chore(release): npm v${VERSION}"
else
  echo "package.json already at version ${VERSION}, skip version bump commit."
fi

git tag "${TAG}"
git push origin "${BRANCH}"
git push origin "${TAG}"

cat <<EOF
Release prepared:
  branch: ${BRANCH}
  tag:    ${TAG}

If repository secret NPM_TOKEN is configured, GitHub Actions will publish to npm automatically.
EOF
