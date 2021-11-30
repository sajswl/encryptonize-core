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

gcloud container clusters get-credentials $OBJ_CLUSTER --zone $ZONE --project $PROJECT

echo -e "${BLUE_ON}[+] Deploying object storage${COLOR_OFF}"
kubectl apply -k "${ROOT_DIR}/object/deploy"

echo -e "${BLUE_ON}[+] Waiting for OSD pods, this can take up to 5 minutes${COLOR_OFF}"
while ! kubectl -n rook-ceph get pods | grep -P "osd-(?!prepare)" > /dev/null; do
  sleep 10
done

echo -e "${BLUE_ON}[+] Waiting for pods to be ready${COLOR_OFF}"
kubectl -n rook-ceph wait --for=condition=Ready pod -l=app=rook-ceph-osd --timeout=300s
sleep 30
kubectl -n rook-ceph wait --for=condition=Ready pod -l=app=rook-ceph-rgw --timeout=120s

# Apply patch through CLI, as kustomize doesn't support patching dynamically created resources
# The deployment 'rook-ceph-rgw-encryptonize-store-a' is created dynamically by Rook
kubectl patch deployment rook-ceph-rgw-encryptonize-store-a -n rook-ceph --patch "$(cat ${ROOT_DIR}/object/deploy/rgw-patch.yaml)"
