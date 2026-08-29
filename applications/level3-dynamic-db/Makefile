# Uniform targets across all four levels: build image push deploy logs verify destroy
#
#   export REGISTRY=<value from documents/environment.md>

LEVEL     := level3-dynamic-db
NAMESPACE := poc-hashicorp-vault-application
TAG       ?= $(shell git rev-parse --short HEAD)
IMAGE      = $(REGISTRY)/$(LEVEL):$(TAG)
OVERLAY   := deploy/overlays/onprem

.PHONY: all build test race image push deploy logs verify destroy require-registry creds query

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(LEVEL) .

test:
	go test ./...

# The lease deadline is written by the lease manager and read by handlers.
# Run this on the dev workspace — the race detector needs cgo and a C compiler,
# which the Windows workstation does not have.
race:
	CGO_ENABLED=1 go test -race ./...

require-registry:
ifndef REGISTRY
	$(error REGISTRY is unset — read it from documents/environment.md, do not guess)
endif

image: require-registry
	podman build -t $(IMAGE) -f Containerfile .

push: require-registry
	podman push $(IMAGE)

deploy: require-registry
	kubectl apply -k $(OVERLAY)

logs:
	kubectl logs -n $(NAMESPACE) -l app=$(LEVEL) -f

# The observation window. Watch `username` and `rotation_count` across a rotation.
creds:
	kubectl -n $(NAMESPACE) port-forward deploy/$(LEVEL) 8080:8080 & \
	sleep 2; curl -s localhost:8080/creds-info | jq

query:
	curl -s localhost:8080/query | jq '{current_user, vault_username, row_count}'

verify:
	@echo "== no TLS bypass (CLAUDE.md rule 3) =="
	@! grep -rnE "InsecureSkipVerify[[:space:]]*[:=][[:space:]]*true" . || (echo "FAIL" && exit 1)
	@echo "OK"
	@echo "== no cross-level imports (D2) =="
	@! grep -nE "level[0-9]" go.mod | grep -v "^module" || (echo "FAIL" && exit 1)
	@echo "OK"
	@go test ./...

destroy:
	kubectl delete -k $(OVERLAY) --ignore-not-found
