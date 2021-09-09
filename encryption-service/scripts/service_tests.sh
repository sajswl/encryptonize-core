#!/bin/bash

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

set -euo pipefail

# Testing with Storage and Encryption API
STORAGE_ENABLED=true ENCRYPTION_ENABLED=true make docker-up
./scripts/e2e_tests.sh
docker-compose stop encryption-service

# Testing with Storage API
STORAGE_ENABLED=true ENCRYPTION_ENABLED=false make docker-up
ENCRYPTION_ENABLED=false ./scripts/e2e_tests.sh
docker-compose stop encryption-service

# Testing with Encryption API
STORAGE_ENABLED=false ENCRYPTION_ENABLED=true make docker-up
STORAGE_ENABLED=false ./scripts/e2e_tests.sh
docker-compose stop encryption-service

# Testing with both API disabled
STORAGE_ENABLED=false ENCRYPTION_ENABLED=false make docker-up
STORAGE_ENABLED=false ENCRYPTION_ENABLED=false ./scripts/e2e_tests.sh
docker-compose down -v
