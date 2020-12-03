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


# Start storage servers
docker-compose up --detach cockroachdb-1 cockroachdb-2 cockroachdb-3 minio minio-init

# Initialise the auth storage
COCKROACH_EXEC="docker-compose exec -T cockroachdb-1 /bin/sh -c"
docker-compose exec -T cockroachdb-1 ./cockroach init --insecure || true
${COCKROACH_EXEC} "echo 'CREATE DATABASE IF NOT EXISTS auth;' | /cockroach/cockroach sql --insecure"
${COCKROACH_EXEC} "/cockroach/cockroach sql --insecure --database auth" < ./data/auth_storage.sql

# Bootstrap admin user
UserID='00000000-0000-4000-8000-000000000002'
TAG='9db265b391c4f9456d3d8ccc9ad367a50c5da1e02abf17ecf0253fb468fa7374'
ADDUSER="UPSERT INTO users (id, tag) VALUES ('${UserID}', X'${TAG}');"
${COCKROACH_EXEC} "echo \"${ADDUSER}\" | /cockroach/cockroach sql --insecure  --database auth"


# testing keys never deploy them!
export KEK=0000000000000000000000000000000000000000000000000000000000000000
export ASK=0000000000000000000000000000000000000000000000000000000000000001

export AUTH_STORAGE_URL='postgresql://root@localhost:26257/auth'
export OBJECT_STORAGE_URL='http://localhost:7000'

export OBJECT_STORAGE_ID=storageid
export OBJECT_STORAGE_KEY=storagekey
# This is just a dummy certificate
export OBJECT_STORAGE_CERT="-----BEGIN CERTIFICATE-----
MIIBpjCCAVigAwIBAgIUQ3byU/Dxv0eA11bPDYVC4xD36dwwBQYDK2VwMGUxCzAJBgNVBAYTAkRLMQowCAYDVQQIDAEuMQowCAYDVQQHDAEuMQwwCgYDVQQKDANmb28xGjAYBgkqhkiG9w0BCQEWC2Zvb0BiYXIuY29tMRQwEgYDVQQDDAtmb28uYmFyLmNvbTAeFw0yMDExMTgxNjM5MDVaFw0yMTExMTgxNjM5MDVaMGUxCzAJBgNVBAYTAkRLMQowCAYDVQQIDAEuMQowCAYDVQQHDAEuMQwwCgYDVQQKDANmb28xGjAYBgkqhkiG9w0BCQEWC2Zvb0BiYXIuY29tMRQwEgYDVQQDDAtmb28uYmFyLmNvbTAqMAUGAytlcAMhAEeBiCvHWsxIRPH6tSqmalACa4ckUhXGLoqFUSLef5jyoxowGDAWBgNVHREEDzANggtmb28uYmFyLmNvbTAFBgMrZXADQQAdA1YAoyBCqsFlePrYO6AP1eUgYfCKEjRUttIeSltIv+M+AEzZIU8+JB3nH684qyi8y7XwWuZVC64639WbLxoL
-----END CERTIFICATE-----"

export ENCRYPTION_SERVICE_INSECURE=1

export TEST_FOLDERS=$(go list ./... | grep -vE '^encryption-service$|e2e_tests|metrics')
echo '[*] testfolders: '
echo $TEST_FOLDERS
echo '[*] running unit tests'
go test -count=1 -coverprofile coverage-unit.out -v $TEST_FOLDERS

echo '[*] starting server in test mode'
go test -coverpkg=./... -coverprofile=coverage-e2e.out -v *.go &

until $(grpc-health-probe -addr=:9000); do
    echo '[*] waiting for the server to be up'
    sleep 1
done

go test -count=1 -v ./tests/grpc_e2e_tests/...

while pkill -x -SIGINT main.test; do
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
