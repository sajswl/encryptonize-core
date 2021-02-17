#!/bin/bash

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

set -euo pipefail

# Run all unit tests and end-to-end tests, generating a merged test coverage report. Usage:
#   ./tests/run-all-tests.sh


source ./scripts/build-env
source ./scripts/dev-env

# Start storage servers
docker-compose up --detach cockroachdb-1 cockroachdb-2 cockroachdb-3 minio minio-init

source ./scripts/db_init.sh

export TEST_FOLDERS=$(go list ./... | grep -vE 'encryption-service$|e2e_tests')
echo '[*] testfolders: '
echo $TEST_FOLDERS
echo '[*] running unit tests'
go test -count=1 -coverprofile coverage-unit.out -v $TEST_FOLDERS

echo '[*] starting server in test mode'
export COMMIT=$(git rev-list -1 HEAD)
export TAG=$(git tag --points-at HEAD)
go test -ldflags "-X 'encryption-service/services/app.GitCommit=$COMMIT' -X 'encryption-service/services/app.GitTag=$TAG'" -coverpkg=./... -coverprofile=coverage-e2e.out -v &

until $(docker run --net=host --rm amothic/grpc-health-probe@sha256:c56a6e93c199cf35a555655de2710528e2f37e50de9f95e3dfb66534803f6155 -addr=:9000); do
    echo '[*] waiting for the server to be up'
    sleep 1
done

go test -count=1 -v ./tests/...

while pkill -f -SIGINT encryption-service.test; do
  echo '[*] waiting for the server to shut down'
  sleep 1
done

echo "[*] generating coverage files"
go tool cover -html=coverage-unit.out -o coverage-unit.html
go tool cover -html=coverage-e2e.out  -o  coverage-e2e.html

gocovmerge coverage-unit.out coverage-e2e.out > coverage-all.out
go tool cover -html=coverage-all.out -o coverage-all.html
rm coverage-*.out

echo '[+] ALL TESTS PASSED'

docker-compose down -v
