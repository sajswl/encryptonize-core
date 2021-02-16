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

# Initialise the auth storage
COCKROACH_EXEC="docker-compose exec -T cockroachdb-1 /bin/sh -c"
docker-compose exec -T cockroachdb-1 ./cockroach init --insecure || true
${COCKROACH_EXEC} "echo 'CREATE DATABASE IF NOT EXISTS auth;' | /cockroach/cockroach sql --insecure"
${COCKROACH_EXEC} "/cockroach/cockroach sql --insecure --database auth" < ./data/auth_storage.sql

# Bootstrap admin user
UserID='00000000-0000-4000-8000-000000000002'
ADDUSER="UPSERT INTO users (id) VALUES ('${UserID}');"
${COCKROACH_EXEC} "echo \"${ADDUSER}\" | /cockroach/cockroach sql --insecure  --database auth"