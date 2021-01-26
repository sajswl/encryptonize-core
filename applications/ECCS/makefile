# Copyright 2020 CYBERCRYPT
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
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make <target> \033[36m\033[0m\n\nTargets:\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)


##### Files #####
binary = eccs
protobufs = app/app.pb.go app/app_grpc.pb.go authn/authn.pb.go authn/authn_grpc.pb.go
protosource = ../../encryption-service/app/app.proto

##### Build targets #####
.PHONY: build
build: $(protobufs)  ## Build the Encryptonize Core Cloud Storage app
	go get -v ./...
	go build -v .

$(protobufs): $(protosource)
	mkdir -p authn
	protoc --go_out=app --go-grpc_out=app --proto_path=../../encryption-service/app app.proto
	protoc --go_out=authn --go-grpc_out=authn --proto_path=../../encryption-service/authn authn.proto

.PHONY: lint
lint: $(protobufs)  ## Lint the codebase
	./scripts/lint.sh

##### Test targets #####
.PHONY: tests
tests: build        ## Run function tests
	./scripts/function_tests.py


##### Cleanup targets #####
.PHONY: clean  ## Remove build artifacts
clean :
	rm -f $(binary)
	rm -f $(protobufs)
	rmdir authn
