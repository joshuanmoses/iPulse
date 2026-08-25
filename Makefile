# iPulse
#
# Common targets. Everything here is a thin wrapper over the scripts in scripts/, so
# the same commands work in CI and by hand.

VERSION ?= $(shell cat VERSION 2>/dev/null || echo 1.0.0)

.PHONY: all build build-all test test-short race cover lint fmt clean \
        install uninstall run deb rpm packages docs help

all: build

## build: compile for the host platform into bin/
build:
	@scripts/build.sh

## build-all: cross-compile every supported platform into dist/
build-all:
	@scripts/build.sh --all

## test: vet, format check, cross-compile check and the full test suite
test:
	@scripts/test.sh

## test-short: skip tests that use the network
test-short:
	@scripts/test.sh --short

## race: run the suite under the race detector
race:
	@scripts/test.sh --race

## cover: run the suite with coverage
cover:
	@scripts/test.sh --cover

## fmt: format the tree
fmt:
	@gofmt -w cmd internal web
	@echo "formatted"

## lint: vet and format check only
lint:
	@go vet ./...
	@test -z "$$(gofmt -l cmd internal web)" || (gofmt -l cmd internal web; exit 1)
	@echo "clean"

## run: run the agent in the foreground from a local directory
run: build
	@IPULSE_HOME=$(CURDIR)/.ipulse-home ./bin/ipulse run

## install: build and install the service (needs root)
install: build
	@scripts/install.sh

## uninstall: stop and remove the service (needs root)
uninstall:
	@scripts/uninstall.sh

## deb: build a Debian package into dist/
# build as well as build-all: the package scripts run ./bin/ipulse to generate the unit.
deb: build build-all
	@packaging/deb/build.sh

## rpm: build an RPM into dist/ (needs rpmbuild)
rpm: build build-all
	@packaging/rpm/build.sh

## packages: build every package
packages: deb rpm

## docs: regenerate the event catalog from the code
docs: build
	@./bin/ipulse events catalog --markdown > docs/event-catalog.md
	@echo "docs/event-catalog.md regenerated"

## clean: remove build output
clean:
	@rm -rf bin dist coverage.out .ipulse-home ipulse-home
	@echo "cleaned"

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
