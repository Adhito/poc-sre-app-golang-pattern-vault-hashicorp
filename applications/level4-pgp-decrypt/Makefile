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

LEVEL     := level4-pgp-decrypt
NAMESPACE := poc-hashicorp-vault-application
TAG       ?= $(shell git rev-parse --short HEAD)
IMAGE      = $(REGISTRY)/$(LEVEL):$(TAG)
OVERLAY   := deploy/overlays/onprem

.PHONY: all build test image push deploy logs verify destroy require-registry require-fixture keystatus tmpfs

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/$(LEVEL) .

test:
	go test ./...

require-registry:
ifndef REGISTRY
	$(error REGISTRY is unset — see this Makefile's header. Do not guess)
endif

# The image is useless without the fixture, and a missing one fails at runtime
# inside the pod rather than at build time. Catch it here.
require-fixture:
	@test -f fixtures/secret-message.txt.gpg || \
		(echo "FAIL: fixtures/secret-message.txt.gpg is missing — it is produced by Stage A Phase A7 step 5. See fixtures/README.md" && exit 1)

image: require-registry require-fixture
	podman build -t $(IMAGE) -f Containerfile .

push: require-registry
	podman push $(IMAGE)

deploy: require-registry
	kubectl apply -k $(OVERLAY)

logs:
	kubectl logs -n $(NAMESPACE) -l app=$(LEVEL) -f

# The level's evidence: `exists` must be false, `on_disk_ms` is the measured window.
keystatus:
	kubectl -n $(NAMESPACE) port-forward deploy/$(LEVEL) 8080:8080 & \
	sleep 2; curl -s localhost:8080/key-status | jq

# Confirm /keys is a real tmpfs and that nothing is left in it.
tmpfs:
	kubectl -n $(NAMESPACE) exec deploy/$(LEVEL) -- df -h /keys
	kubectl -n $(NAMESPACE) exec deploy/$(LEVEL) -- ls -la /keys

verify:
	@echo "== no TLS bypass (CLAUDE.md rule 3) =="
	@! grep -rnE "InsecureSkipVerify[[:space:]]*[:=][[:space:]]*true" . || (echo "FAIL" && exit 1)
	@echo "OK"
	@echo "== the maintained openpgp fork, not the deprecated one (D10) =="
	@! grep -q "golang.org/x/crypto/openpgp" go.mod || (echo "FAIL: deprecated x/crypto/openpgp" && exit 1)
	@grep -q "ProtonMail/go-crypto" go.mod || (echo "FAIL: expected ProtonMail/go-crypto" && exit 1)
	@echo "OK"
	@echo "== no key material committed =="
	@! git ls-files | grep -E '\.(asc|key)$$' || (echo "FAIL: key material tracked in git" && exit 1)
	@echo "OK"
	@go test ./...

destroy:
	kubectl delete -k $(OVERLAY) --ignore-not-found
