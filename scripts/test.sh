#!/usr/bin/env bash
#
# Run the iPulse test suite.
#
#   scripts/test.sh              unit and integration tests
#   scripts/test.sh --short      skip the tests that use the network
#   scripts/test.sh --race       with the race detector
#   scripts/test.sh --cover      with a coverage summary
#
# The suite is designed to pass with no Internet access: every test that needs the
# network is either skipped in short mode or runs against a local server.

set -euo pipefail
cd "$(dirname "$0")/.."

ARGS=(./...)
FLAGS=()

for arg in "$@"; do
  case "$arg" in
    --short) FLAGS+=(-short) ;;
    --race)  FLAGS+=(-race) ;;
    --cover) FLAGS+=(-coverprofile=coverage.out -covermode=atomic) ;;
    *) FLAGS+=("$arg") ;;
  esac
done

echo "== go vet =="
go vet ./...

echo
echo "== gofmt =="
unformatted=$(gofmt -l cmd internal web 2>/dev/null || true)
if [ -n "$unformatted" ]; then
  echo "These files need gofmt:" >&2
  echo "$unformatted" >&2
  exit 1
fi
echo "  all files formatted"

echo
echo "== cross-compilation =="
for platform in linux/amd64 linux/arm64 linux/arm windows/amd64 windows/arm64; do
  GOOS="${platform%/*}" GOARCH="${platform#*/}" CGO_ENABLED=0 go build -o /dev/null ./... \
    && echo "  ${platform} ok"
done

echo
echo "== tests =="
go test "${FLAGS[@]}" "${ARGS[@]}"

if [ -f coverage.out ]; then
  echo
  echo "== coverage =="
  go tool cover -func=coverage.out | tail -1
fi
