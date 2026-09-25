# `go install` puts the tool in GOBIN, which is not on PATH in every shell, and
# GNU Make 3.81 resolves a bare command name against the environment rather than
# an exported makefile PATH. Prefer the GOBIN copy -- the one lint_install
# writes, which is version-pinned -- and fall back to whatever PATH resolves.
# Override with `make lint GOLANGCI_LINT=...`.
GOLANGCI_LINT ?= $(firstword $(wildcard $(shell go env GOPATH)/bin/golangci-lint) golangci-lint)

# Formatting comes from .golangci.yml so that `make fmt`, `make lint` and CI
# all agree on one definition.
#
# gci is deliberately not part of it. The section order this target used to
# declare (standard, then GoAsyncFunc, then everything else) is not what the
# tree follows -- about 18 files would be rewritten, and the repository is not
# consistent about it either way. Enforcing one order is a separate decision
# from making the lint gate real; until it is made, no import order is checked.
fmt:
	@$(GOLANGCI_LINT) fmt

fmt_install:
	go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0

# The four-GOOS sweep is deliberate: CI builds only the host GOOS, so nothing
# else type-checks the platform-specific code. This target is the local half of
# the gate; CI runs the same config on linux only.
lint:
	@for os in linux windows darwin freebsd; do \
		echo "lint $$os"; \
		GOOS=$$os $(GOLANGCI_LINT) run --timeout 5m || exit 1; \
	done

lint_install:
	go install -v github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0

# GitHub Actions workflow files. There is no official actionlint action, so CI
# calls these targets rather than repeating the version -- the pin below is the
# only one in the tree. `go install` also gets the binary verified through the
# module proxy and checksum database; actionlint's own download script does not
# check a hash, and it fetches itself from `main`.
#
# shellcheck is used automatically when it is on PATH. ubuntu-latest (what CI
# runs on) ships it; a bare macOS box does not, so locally this checks the
# workflow YAML but not the shell inside `run:` blocks. `brew install
# shellcheck` closes that gap.
ACTIONLINT_VERSION ?= v1.7.12
ACTIONLINT ?= $(firstword $(wildcard $(shell go env GOPATH)/bin/actionlint) actionlint)

actionlint:
	@$(ACTIONLINT) -color .github/workflows/*.yml

actionlint_install:
	go install -v github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

test:
	go test ./...
