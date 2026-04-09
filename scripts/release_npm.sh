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

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required."
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

VERSION="${VERSION}" python3 - <<'PY'
import json
import os
import re
from pathlib import Path

version = os.environ["VERSION"]

package_path = Path("package.json")
package = json.loads(package_path.read_text(encoding="utf-8"))
package["version"] = version
package_path.write_text(json.dumps(package, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

pyproject_path = Path("pyproject.toml")
pyproject = pyproject_path.read_text(encoding="utf-8")
pyproject = re.sub(r'^version = ".*"$', f'version = "{version}"', pyproject, count=1, flags=re.MULTILINE)
pyproject_path.write_text(pyproject, encoding="utf-8")

init_path = Path("src/lazysre/__init__.py")
init_text = init_path.read_text(encoding="utf-8")
init_text = re.sub(r'^__version__ = ".*"$', f'__version__ = "{version}"', init_text, count=1, flags=re.MULTILINE)
init_path.write_text(init_text, encoding="utf-8")
PY

if [[ -x "./scripts/check_npm_release.sh" ]]; then
  echo "[release] running npm preflight checks..."
  ./scripts/check_npm_release.sh "${VERSION}"
fi

if git diff --quiet -- package.json pyproject.toml src/lazysre/__init__.py; then
  echo "package.json/pyproject.toml/__init__.py already at version ${VERSION}, skip version bump commit."
else
  git add package.json pyproject.toml src/lazysre/__init__.py
  git commit -m "chore(release): v${VERSION}"
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
