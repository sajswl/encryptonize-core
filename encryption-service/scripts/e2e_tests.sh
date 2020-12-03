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

# Run all end-to-end tests. Requires an Encryption Server to be running. Usage:
#   ./scripts/unit_tests.sh
#
# By default the tests are run on a local server. To change this behaviour, the following
# environment variables can be set:
#
# - E2E_TEST_URL       : Server endpoint
# - E2E_TEST_ADMIN_UID : Admin user ID
# - E2E_TEST_ADMIN_UAT : Admin user access token
# - E2E_TEST_HTTPS     : Set to "true" if testing an HTTPS endpoint

set -euo pipefail

export ENCRYPTION_SERVICE_INSECURE=1

echo '[*] running end-to-end tests'
go test -count=1 -v ./tests/grpc_e2e_tests/...
