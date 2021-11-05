# Copyright 2021 CYBERCRYPT
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

##### Help message #####
help:  ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target> \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z0-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)


##### Config #####
# Change shell to bash to allow sourcing of env variables
SHELL := /bin/bash

##### Files #####
binary = encryption-service
protobufs = services/authz/authz.pb.go services/authz/authz_grpc.pb.go services/storage/storage_grpc.pb.go services/storage/storage.pb.go services/authn/authn_grpc.pb.go services/authn/authn.pb.go services/enc/enc.pb.go services/enc/enc_grpc.pb.go services/app/app_grpc.pb.go services/app/app.pb.go common/users.pb.go
protosource = services/authz/authz.proto services/storage/storage.proto services/authn/authn.proto services/app/app.proto common/users.proto services/enc/enc.proto
protocopts = --go_opt=paths=source_relative --go_out=.
grpcopts = $(protocopts) --go-grpc_opt=paths=source_relative --go-grpc_out=.
credentials = data/client.root.crt data/object_storage_key data/ca.crt data/client.root.key data/encryptonize.crt data/object_storage_id data/object_storage.crt
coverage = coverage-unit.html coverage-e2e.html coverage-all.html

# Build Tags variable
tags =

# Linker flags variable
ldflags =

# Scopes set when creating users
scopes = rcudiom

##### Build targets #####
.PHONY: build
build: git-commit=$(shell git rev-list -1 HEAD)
build: git-tag=$(shell git tag --points-at HEAD)
build: ldflags += -X 'encryption-service/services/app.GitCommit=${git-commit}'
build: ldflags += -X 'encryption-service/services/app.GitTag=${git-tag}'
build: $(protobufs)  ## Build the Encryption Service binary
	source ./scripts/build-env && go build -v -ldflags "$(ldflags)" -tags "$(tags)" .

$(protobufs): $(protosource)
	protoc $(grpcopts) services/storage/storage.proto
	protoc $(grpcopts) services/enc/enc.proto
	protoc $(grpcopts) services/authz/authz.proto
	protoc $(grpcopts) services/authn/authn.proto
	protoc $(grpcopts) services/app/app.proto
	protoc $(protocopts) common/users.proto

.PHONY: docker-build
docker-build:  ## Build the Encryption Service docker image
	./scripts/docker_build.sh

.PHONY: snyk-scan-image
snyk-scan-image: docker-build ## Scan the encryptonize image for vulnerable dependencies
	./scripts/docker_scan.sh

.PHONY: snyk-scan-golang
snyk-scan-golang:  ## Scan the golang dependencies for known vulnerabilities
	./scripts/golang_scan.sh

# Only pull credentials if they don't exist already
.PHONY: credentials
credentials: | $(credentials)  ## See scripts/get_credentials.sh for details

$(credentials):
	./scripts/get_credentials.sh

.PHONY: lint
lint: $(protobufs)  ## Lint the codebase
	./scripts/lint.sh


##### Test targets #####
.PHONY: tests
tests: unit-tests service-tests eccs-tests ## Run all tests

.PHONY: coverage
coverage: build  ## Generate coverage report
	./scripts/coverage.sh

.PHONY: unit-tests
unit-tests: build  ## Run unit tests
	./scripts/unit_tests.sh

.PHONY: e2e-tests
e2e-tests: build  ## Run end-to-end tests
	./scripts/e2e_tests.sh

.PHONY: e2e-tests-local
e2e-tests-local: build  ## Run end-to-end tests against a local instance
	source <(./scripts/get-e2e-user.sh local) && \
	./scripts/e2e_tests.sh

.PHONY: e2e-tests-docker
e2e-tests-docker: build  ## Run end-to-end tests against docker
	$(MAKE) docker-up
	source <(./scripts/get-e2e-user.sh docker) && \
	./scripts/e2e_tests.sh
	$(MAKE) docker-down

.PHONY: e2e-tests-kubernetes
e2e-tests-kubernetes: build  ## Run end-to-end tests against kubernetes
	source <(./scripts/get-e2e-user.sh kubernetes) && \
	./scripts/e2e_tests.sh

.PHONY: service-tests
service-tests: build  ## Run end-to-end tests while enabling/disabling services
	$(MAKE) docker-up
	source <(./scripts/get-e2e-user.sh docker) && \
	./scripts/service_tests.sh

.PHONY: eccs-tests
eccs-tests:  ## Run tests of the ECCS application
	$(MAKE) docker-up
	source <(./scripts/get-e2e-user.sh docker) && \
	$(MAKE) -C ../applications/ECCS tests
	$(MAKE) docker-down


##### Run targets #####
.PHONY: run
run: build  ## Start a local instance of the Encryption Service
	./scripts/run.sh

.PHONY: run-in-mem
run-in-mem: tags += storage_mocked
run-in-mem: build  ## Start a local instance of the Encryption Service with mock backends
	./scripts/run.sh

.PHONY: create-user
create-user: build  ## Creates a user with all scopes for the local instance of the Encryption Service
	./scripts/run.sh create-user $(scopes)

.PHONY: create-user-mem
create-user-mem: tags += storage_mocked
create-user-mem: build  ## Creates a user with all scopes for the local instance of the Encryption Service
	./scripts/run.sh create-user $(scopes)

.PHONY: docker-up
docker-up:  ## Start a dockerized instance of the Encryption Service
	./scripts/docker_up.sh --detach

.PHONY: docker-down
docker-down:  ## Stop a dockerized instance of the Encryption Service
	docker-compose down -v

.PHONY: docker-create-user
docker-create-user: docker-up  ## Creates a user with all scopes for the dockerized instance of the Encryption Service
	docker-compose run encryption-service create-user $(scopes)

##### Cleanup targets #####
.PHONY: clean  ## Remove build artifacts
clean :
	rm -f $(binary)
	rm -f $(protobufs)
	rm -f $(coverage)

.PHONY: clean-credentials  ## Remove credentials
clean-credentials :
	rm -f $(credentials)
