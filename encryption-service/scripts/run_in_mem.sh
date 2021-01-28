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

# Start a local version of the Encryption Service on localhost. Usage:
#   ./scripts/run.sh [args]
#
# The environment variables below can be set to modify the configuration of the service.

# Static compilation
export CGO_ENABLED=0

# testing keys never deploy them!
export KEK=0000000000000000000000000000000000000000000000000000000000000000
export ASK=0000000000000000000000000000000000000000000000000000000000000001

export AUTH_STORAGE_URL=''
export OBJECT_STORAGE_URL=''

export OBJECT_STORAGE_ID=storageid
export OBJECT_STORAGE_KEY=storagekey
# This is just a dummy certificate
export OBJECT_STORAGE_CERT="-----BEGIN CERTIFICATE-----
MIIBpjCCAVigAwIBAgIUQ3byU/Dxv0eA11bPDYVC4xD36dwwBQYDK2VwMGUxCzAJBgNVBAYTAkRLMQowCAYDVQQIDAEuMQowCAYDVQQHDAEuMQwwCgYDVQQKDANmb28xGjAYBgkqhkiG9w0BCQEWC2Zvb0BiYXIuY29tMRQwEgYDVQQDDAtmb28uYmFyLmNvbTAeFw0yMDExMTgxNjM5MDVaFw0yMTExMTgxNjM5MDVaMGUxCzAJBgNVBAYTAkRLMQowCAYDVQQIDAEuMQowCAYDVQQHDAEuMQwwCgYDVQQKDANmb28xGjAYBgkqhkiG9w0BCQEWC2Zvb0BiYXIuY29tMRQwEgYDVQQDDAtmb28uYmFyLmNvbTAqMAUGAytlcAMhAEeBiCvHWsxIRPH6tSqmalACa4ckUhXGLoqFUSLef5jyoxowGDAWBgNVHREEDzANggtmb28uYmFyLmNvbTAFBgMrZXADQQAdA1YAoyBCqsFlePrYO6AP1eUgYfCKEjRUttIeSltIv+M+AEzZIU8+JB3nH684qyi8y7XwWuZVC64639WbLxoL
-----END CERTIFICATE-----"

export ENCRYPTION_SERVICE_INSECURE=1

echo '[*] starting Encryption Service with mock backends'
go test -v *.go -run InMemoryMain
