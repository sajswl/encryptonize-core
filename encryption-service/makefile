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
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target> \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)


##### Files #####
binary = encryption-service
protobufs = app/app_grpc.pb.go app/app.pb.go authn/authn_grpc.pb.go authn/authn.pb.go authz/access_object.pb.go
protosource = app/app.proto authn/authn.proto authz/access_object.proto
credentials = data/client.root.crt data/object_storage_key data/ca.crt data/client.root.key data/encryptonize.crt data/object_storage_id data/object_storage.crt
coverage = coverage-unit.html coverage-e2e.html coverage-all.html

# Build Tags variable
tags =

##### Build targets #####
.PHONY: build
build: $(protobufs)  ## Build the Encryption Service binary
	CGO_ENABLED=0 go build -v -tags "$(tags)" .

$(protobufs): $(protosource)
	protoc --go-grpc_out=app --go_out=app app/app.proto
	protoc --go-grpc_out=authn --go_out=authn authn/authn.proto
	protoc --go_out=authz authz/access_object.proto

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
