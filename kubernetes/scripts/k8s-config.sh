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

# TODO: This is the bootstrapping part for Encryptonize.
# We need to figure out exactly what to do here and how to do it.

set -euo pipefail

source ./scripts/encryptonize_env # Read kubernetes related configs into environment

# Create encryptonize config
envsubst < encryption-service/encryptonize-config.yaml | kubectl apply -f - 

# Create file secrets

# Create pull secret

# Deploy cert-manager
