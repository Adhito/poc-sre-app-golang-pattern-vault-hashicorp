# Uniform targets across all four levels: build image push deploy logs verify destroy
#
# REGISTRY has no default on purpose. It is recorded by Stage A Phase A0 in
# environment.md, which lives in the CLUSTER repo, not this one:
#
#   poc-platform-engineering-iac-vagrant-ansible-k8s-cluster-kubeadm-calico
#     script-manifest/utility-hashicorp-vault/documents/environment.md
#
# Still marked unverified there.
#
#   export REGISTRY=<the value from that file>

LEVEL     := level2-k8s-auth
NAMESPACE := poc-hashicorp-vault-application
TAG       ?= $(shell git rev-parse --short HEAD)
IMAGE      = $(REGISTRY)/$(LEVEL):$(TAG)
OVERLAY   := deploy/overlays/onprem

.PHONY: all build test image push deploy logs verify destroy require-registry

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(LEVEL) .

test:
	go test ./...

require-registry:
ifndef REGISTRY
	$(error REGISTRY is unset — see this Makefile's header. Do not guess)
endif

image: require-registry
	podman build -t $(IMAGE) -f Containerfile .

push: require-registry
	podman push $(IMAGE)

deploy: require-registry
	kubectl apply -k $(OVERLAY)

logs:
	kubectl logs -n $(NAMESPACE) -l app=$(LEVEL) -f

# Phase B2 mechanical gates. The SDK check is re-run in B5 across all modules.
verify:
	@echo "== no Vault SDK in this module (D3) =="
	@! grep -q "hashicorp/vault" go.mod || (echo "FAIL: SDK dependency present" && exit 1)
	@test ! -f go.sum || (echo "FAIL: go.sum exists — this module must have zero dependencies" && exit 1)
	@echo "OK"
# Match the ASSIGNMENT, not the identifier: vault_login_test.go legitimately
# references the field to assert it is false. A bare `grep InsecureSkipVerify`
# would flag the test that proves the rule is held.
	@echo "== no TLS bypass anywhere (CLAUDE.md rule 3) =="
	@! grep -rnE "InsecureSkipVerify[[:space:]]*[:=][[:space:]]*true" . || (echo "FAIL" && exit 1)
	@echo "OK"
	@go test ./...

destroy:
	kubectl delete -k $(OVERLAY) --ignore-not-found
