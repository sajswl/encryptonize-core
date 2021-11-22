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

source ./scripts/dev-env

USER_INFO=""

if [[ "${1}" == "local" ]]; then
  USER_INFO=$(./encryption-service create-user m 2> /dev/null)
elif [[ "${1}" == "docker" ]]; then
  USER_INFO=$(docker exec encryption-service /encryption-service create-user m 2> /dev/null)
elif [[ "${1}" == "kubernetes" ]]; then
  USER_INFO=$(kubectl -n encryptonize exec -it deployment/encryptonize-deployment -- /encryption-service create-user m | tail -n 1)
else
  echo "Unknown argument '${1}'"
  exit 1
fi

echo "export E2E_TEST_UID=$(echo $USER_INFO | jq -r ".user_id")"
echo "export E2E_TEST_PASS=$(echo $USER_INFO | jq -r ".password")"
