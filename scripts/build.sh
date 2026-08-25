#!/usr/bin/env bash
#
# Build iPulse binaries.
#
#   scripts/build.sh                 build for the host platform into bin/
#   scripts/build.sh --all           cross-compile every supported platform into dist/
#   scripts/build.sh --platform linux/arm64
#
# The build is fully static: iPulse uses a pure-Go SQLite driver so CGO is never
# needed, which is what makes a single self-contained binary per platform possible.

set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${IPULSE_VERSION:-$(cat VERSION 2>/dev/null || echo 1.0.0)}"
COMMIT="${IPULSE_COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
BUILD_DATE="${IPULSE_BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"

MODULE="github.com/ipulse/ipulse"
LDFLAGS="-s -w"
LDFLAGS="$LDFLAGS -X ${MODULE}/internal/version.Version=${VERSION}"
LDFLAGS="$LDFLAGS -X ${MODULE}/internal/version.Commit=${COMMIT}"
LDFLAGS="$LDFLAGS -X ${MODULE}/internal/version.BuildDate=${BUILD_DATE}"

PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "linux/arm"
  "windows/amd64"
  "windows/arm64"
)

build_one() {
  local goos="$1" goarch="$2" outdir="$3"
  local name="ipulse"
  [ "$goos" = "windows" ] && name="ipulse.exe"

  local target="${outdir}/${goos}-${goarch}/${name}"
  mkdir -p "$(dirname "$target")"

  echo "  building ${goos}/${goarch}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$target" ./cmd/ipulse
}

case "${1:-}" in
  --all)
    echo "iPulse ${VERSION} (${COMMIT})"
    rm -rf dist
    for platform in "${PLATFORMS[@]}"; do
      build_one "${platform%/*}" "${platform#*/}" dist
    done
    echo
    echo "Artifacts:"
    find dist -type f -exec ls -lh {} \; | awk '{printf "  %-46s %s\n", $NF, $5}'
    ;;
  --platform)
    [ $# -ge 2 ] || { echo "usage: $0 --platform <goos/goarch>" >&2; exit 2; }
    build_one "${2%/*}" "${2#*/}" dist
    ;;
  "")
    mkdir -p bin
    echo "iPulse ${VERSION} (${COMMIT}) for the host platform"
    CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o bin/ipulse ./cmd/ipulse
    echo "  bin/ipulse"
    ;;
  *)
    echo "usage: $0 [--all | --platform <goos/goarch>]" >&2
    exit 2
    ;;
esac
