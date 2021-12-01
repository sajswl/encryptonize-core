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
OUT_DIR="${ROOT_DIR}/logging/deploy/config"

mkdir -p "${OUT_DIR}"

echo -e "${BLUE_ON}[+] Fetching Elasticsearch credentials${COLOR_OFF}"
gcloud container clusters get-credentials $AUTH_CLUSTER --zone $ZONE --project $PROJECT

kubectl -n elasticsearch get secrets elasticsearch-es-http-certs-public -o jsonpath="{.data['tls\.crt']}" | base64 -d > "${OUT_DIR}/elastic.crt"
kubectl -n elasticsearch get secrets elasticsearch-es-http-certs-public -o jsonpath="{.data['ca\.crt']}" | base64 -d > "${OUT_DIR}/elastic-ca.crt"
kubectl -n elasticsearch get secret elasticsearch-es-elastic-user -o go-template='{{.data.elastic | base64decode}}' > "${OUT_DIR}/elastic-password"

echo -e "${BLUE_ON}[+] Deploying log monitoring to auth cluster${COLOR_OFF}"
gcloud container clusters get-credentials $AUTH_CLUSTER --zone $ZONE --project $PROJECT
kubectl apply -k "${ROOT_DIR}/logging/deploy"

echo -e "${BLUE_ON}[+] Deploying log monitoring to object cluster${COLOR_OFF}"
gcloud container clusters get-credentials $OBJ_CLUSTER --zone $ZONE --project $PROJECT
kubectl apply -k "${ROOT_DIR}/logging/deploy"

echo -e "${BLUE_ON}[+] Deploying log monitoring to Encryptonize cluster${COLOR_OFF}"
gcloud container clusters get-credentials $ENC_CLUSTER --zone $ZONE --project $PROJECT
kubectl apply -k "${ROOT_DIR}/logging/deploy"
