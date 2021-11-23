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

BLUE_ON="\u1b[1;34m"
COLOR_OFF="\u1b[m"

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && cd .. && pwd )"

gcloud container clusters get-credentials $ENC_CLUSTER --zone $ZONE --project $PROJECT

echo -e "${BLUE_ON}[+] Deploying encryptonize cluster${COLOR_OFF}"
kubectl apply -k "${ROOT_DIR}/encryptonize/deploy"
kubectl -n encryptonize rollout restart deployment encryptonize
kubectl -n encryptonize rollout status deployment encryptonize
kubectl -n encryptonize rollout restart deployment encryptonize-ingress
kubectl -n encryptonize rollout status deployment encryptonize-ingress
