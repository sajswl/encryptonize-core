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

# Generate configs
./scripts/substitute-configs.sh

# Deploy Encryptonize
gcloud container clusters get-credentials $ENC_CLUSTER --zone $ZONE --project $PROJECT
kubectl apply -k encryptonize/
kubectl -n encryptonize rollout restart deployment encryptonize-deployment
kubectl -n encryptonize rollout restart deployment encryptonize-ingress

# Deploy object storage
gcloud container clusters get-credentials $OBJ_CLUSTER --zone $ZONE --project $PROJECT
kubectl apply -k rook-ceph/
# Apply patch through CLI, as kustomize doesn't support patching dynamically created resources
# The deployment 'rook-ceph-rgw-encryptonize-store-a' is created dynamically by Rook
kubectl patch deployment rook-ceph-rgw-encryptonize-store-a -n rook-ceph --patch "$(cat rook-ceph/rgw-patch.yaml)"

# Deploy auth storage
gcloud container clusters get-credentials $AUTH_CLUSTER --zone $ZONE --project $PROJECT
kubectl apply -k cockroachdb/
kubectl -n cockroachdb -c cockroachdb exec -it cockroachdb-0 -- /bin/sh -c "
  echo 'CREATE USER IF NOT EXISTS encryptonize;' | /cockroach/cockroach sql --certs-dir /cockroach/cockroach-certs;
  echo 'CREATE DATABASE IF NOT EXISTS auth;' | /cockroach/cockroach sql --certs-dir /cockroach/cockroach-certs;
  echo 'GRANT ALL ON DATABASE auth TO encryptonize;' | /cockroach/cockroach sql --certs-dir /cockroach/cockroach-certs
"
