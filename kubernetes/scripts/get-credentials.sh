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

# Fetches certificates and credentials from encryptonize clusters. Supposed to be used with the
# setup described in `kubernetes/README.md`. Set the the `PROJECT` environment variable before
# running the script. Usage:
#     ./_scripts/get_credentials.sh

set -euo pipefail

BLUE_ON="\u1b[1;34m"
COLOR_OFF="\u1b[m"

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && cd .. && pwd )"
OUT_DIR="${ROOT_DIR}/credentials"

mkdir -p ${OUT_DIR}

echo -e "${BLUE_ON}[+] Fetching auth store certificates and client key${COLOR_OFF}"

gcloud container clusters get-credentials $AUTH_CLUSTER --zone $ZONE --project $PROJECT
kubectl -n cockroachdb exec -it cockroachdb-0 -c cockroachdb -- cat /cockroach/cockroach-certs/ca.crt  > ${OUT_DIR}/ca.crt
kubectl -n cockroachdb get secrets cockroachdb.client.root -o jsonpath="{.data['cert']}" | base64 -d > ${OUT_DIR}/client.root.crt
kubectl -n cockroachdb get secrets cockroachdb.client.root -o jsonpath="{.data['key']}" | base64 -d > ${OUT_DIR}/client.root.key

echo -e "${BLUE_ON}[+] Fetching object store credentials${COLOR_OFF}"

gcloud container clusters get-credentials $OBJ_CLUSTER --zone $ZONE --project $PROJECT
kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_ACCESS_KEY_ID']}" | base64 -d > ${OUT_DIR}/object_storage_id
kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_SECRET_ACCESS_KEY']}" | base64 -d > ${OUT_DIR}/object_storage_key
kubectl -n rook-ceph get secret object-certs -o jsonpath="{.data.object_storage\.crt}" | base64 -d > ${OUT_DIR}/object_storage.crt

echo -e "${BLUE_ON}[+] Fetching Encryptonize certificate${COLOR_OFF}"

gcloud container clusters get-credentials $ENC_CLUSTER --zone $ZONE --project $PROJECT
kubectl -n encryptonize get secret ingress-certificate -o jsonpath="{.data['tls\.crt']}" | base64 -d > ${OUT_DIR}/encryptonize.crt
