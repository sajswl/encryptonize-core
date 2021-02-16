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

# Start a containerized version of the Encryption Service using docker compose. Usage
#   ./scripts/docker_up.sh <args>
#
# Anything passed as <args> will be passed on to `docker-compose up`.

set -euo pipefail

# Required to make <dockerfile>.dockerignore work, which we need since we need
# the build context to be `../..` in encryptonize-premium
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Start the docker containers
docker-compose build --build-arg COMMIT="$(git rev-list -1 HEAD)" --build-arg TAG="$(git tag --points-at HEAD)"
docker-compose up $@

source ./scripts/db_init.sh