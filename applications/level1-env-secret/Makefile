# Uniform targets across all four levels: build image push deploy logs verify destroy
#
# REGISTRY has no default on purpose. The real value is read off the live
# cluster in Stage A Phase A0 and recorded in environment.md — which lives in
# the CLUSTER repo, beside the Stage A manifests, not in this one:
#
#   poc-platform-engineering-iac-vagrant-ansible-k8s-cluster-kubeadm-calico
#     script-manifest/utility-hashicorp-vault/documents/environment.md
#
# REGISTRY is still marked unverified there. Guessing it is exactly the
# failure CLAUDE.md forbids.
#
#   export REGISTRY=<the value from that file>

LEVEL     := level1-env-secret
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

# Phase B1 verification. The grep is the deliverable: this module must have no
# knowledge of the secrets backend at all (PRD Stage B, Phase B1 step 2).
verify:
	@echo "== source must not reference the secrets backend =="
	@! grep -ri vault main.go go.mod || (echo "FAIL: backend reference in source" && exit 1)
	@echo "OK"
	@echo "== endpoint =="
	kubectl -n $(NAMESPACE) exec deploy/$(LEVEL) -- wget -qO- localhost:8080/secret || \
		echo "(distroless has no shell — use: kubectl -n $(NAMESPACE) port-forward deploy/$(LEVEL) 8080:8080)"

destroy:
	kubectl delete -k $(OVERLAY) --ignore-not-found
