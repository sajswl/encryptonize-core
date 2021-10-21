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

envsubst '${ENCRYPTION_SERVICE_IMAGE}'  < encryption-service/encryptonize-service.yaml | kubectl apply -f -
envsubst '${ENCRYPTION_SERVICE_HOSTNAME}' < encryption-service/encryptonize-ingress.yaml | kubectl apply -f -
kubectl -n encryptonize rollout restart deployment encryptonize-deployment
kubectl -n encryptonize rollout restart deployment encryptonize-ingress
