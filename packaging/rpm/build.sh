#!/usr/bin/env bash
#
# Build an RPM for iPulse.
#
#   packaging/rpm/build.sh [x86_64|aarch64]
#
# Requires rpmbuild. The binary is built beforehand by scripts/build.sh --all: iPulse
# cross-compiles cleanly, so the package host does not need a Go toolchain.

set -euo pipefail
cd "$(dirname "$0")/../.."

ARCH="${1:-x86_64}"
VERSION="$(cat VERSION 2>/dev/null || echo 1.0.0)"

case "$ARCH" in
  x86_64)  GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
  *) echo "unsupported architecture: $ARCH" >&2; exit 2 ;;
esac

command -v rpmbuild >/dev/null 2>&1 || {
  echo "rpmbuild is not installed." >&2
  echo "  Fedora/RHEL: sudo dnf install rpm-build systemd-rpm-macros" >&2
  echo "  Debian/Ubuntu: sudo apt install rpm" >&2
  exit 1
}

BINARY="dist/linux-${GOARCH}/ipulse"
[ -x "$BINARY" ] || { echo "missing $BINARY; run scripts/build.sh --all first" >&2; exit 1; }

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp "$BINARY" "$TOP/SOURCES/ipulse"
cp configs/ipulse.yaml "$TOP/SOURCES/ipulse.yaml"
./bin/ipulse service unit > "$TOP/SOURCES/ipulse.service"
cp packaging/rpm/ipulse.spec "$TOP/SPECS/"

# Documentation travels as sources, so the package builds from artifacts alone.
cp README.md LICENSE CHANGELOG.md "$TOP/SOURCES/"
tar czf "$TOP/SOURCES/docs.tar.gz" -C docs .

# _buildhost is pinned so the packager's hostname does not ship in the RPM header.
rpmbuild --define "_topdir $TOP" \
         --define "_version $VERSION" \
         --define "_buildhost localhost" \
         --target "$ARCH" \
         -bb "$TOP/SPECS/ipulse.spec"

mkdir -p dist
find "$TOP/RPMS" -name '*.rpm' -exec cp {} dist/ \;
echo
echo "built:"
find dist -name "ipulse-${VERSION}*.rpm" -exec ls -lh {} \; | awk '{printf "  %s  %s\n", $NF, $5}'
