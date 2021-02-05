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


##### Files #####
binary = encryption-service
protobufs = services/enc/enc_grpc.pb.go services/enc/enc.pb.go services/authn/authn_grpc.pb.go services/authn/authn.pb.go services/app/app_grpc.pb.go services/app/app.pb.go impl/authz/access_object.pb.go scopes/scopes.pb.go
protosource = services/enc/enc.proto services/authn/authn.proto services/app/app.proto impl/authz/access_object.proto scopes/scopes.proto
protocopts = --go_opt=paths=source_relative --go_out=.
grpcopts = $(protocopts) --go-grpc_opt=paths=source_relative --go-grpc_out=.
credentials = data/client.root.crt data/object_storage_key data/ca.crt data/client.root.key data/encryptonize.crt data/object_storage_id data/object_storage.crt
coverage = coverage-unit.html coverage-e2e.html coverage-all.html

# Build Tags variable
tags =

# Linker flags variable
ldflags =

##### Build targets #####
.PHONY: build
build: $(protobufs)  ## Build the Encryption Service binary
	CGO_ENABLED=0 go build -v -ldflags "$(ldflags)" -tags "$(tags)" .

$(protobufs): $(protosource)
	protoc $(grpcopts) services/enc/enc.proto
	protoc $(grpcopts) services/authn/authn.proto
	protoc $(grpcopts) services/app/app.proto
	protoc $(protocopts) impl/authz/access_object.proto
	protoc $(protocopts) scopes/scopes.proto

.PHONY: docker-build
docker-build:  ## Build the Encryption Service docker image
	./scripts/docker_build.sh

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
tests: unit-tests e2e-tests eccs-tests ## Run all tests

.PHONY: coverage
coverage: build  ## Generate coverage report
	./scripts/coverage.sh

.PHONY: unit-tests
unit-tests: build  ## Run unit tests
	./scripts/unit_tests.sh

.PHONY: e2e-tests
e2e-tests: build  ## Run end-to-end tests
	./scripts/e2e_tests.sh

.PHONY: eccs-tests
eccs-tests: build ## Run tests of the ECCS application
	$(MAKE) -C ../applications/ECCS tests


##### Run targets #####
.PHONY: run
run: build  ## Start a local instance of the Encryption Service
	./scripts/run.sh

.PHONY: run-in-mem
run-in-mem: tags += storage_mocked
run-in-mem: build  ## Start a local instance of the Encryption Service with mock backends
	./scripts/run.sh

.PHONY: create-admin
create-admin: build  ## Creates an admin for the local instance of the Encryption Service
	./scripts/run.sh create-admin

.PHONY: create-admin-mem
create-admin-mem: tags += storage_mocked
create-admin-mem: build  ## Creates an admin for the local instance of the Encryption Service
	./scripts/run.sh create-admin

.PHONY: docker-up
docker-up:  ## Start a dockerized instance of the Encryption Service
	./scripts/docker_up.sh --detach

.PHONY: docker-down
docker-down:  ## Stop a dockerized instance of the Encryption Service
	docker-compose down -v

.PHONY: docker-create-admin
docker-create-admin: docker-up  ## Creates an admin for the dockerized instance of the Encryption Service
	docker-compose run encryption-service create-admin

##### Cleanup targets #####
.PHONY: clean  ## Remove build artifacts
clean :
	rm -f $(binary)
	rm -f $(protobufs)
	rm -f $(coverage)

.PHONY: clean-credentials  ## Remove credentials
clean-credentials :
	rm -f $(credentials)
