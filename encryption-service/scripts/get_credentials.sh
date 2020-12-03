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

# Fetches certificates and credentials from encryptonize clusters. Supposed to be used with the
# setup described in `kubernetes/README.md`. Set the the `PROJECT` environment variable before
# running the script. Usage:
#     ./_scripts/get_db_certificates.sh

set -euo pipefail

DATA="./data"

echo "[*] switching to GCloud project"

gcloud config set project ${PROJECT}


echo "[*] fetching CockroachDB certificates and client key"

gcloud container clusters get-credentials encryptonize-auth --zone=europe-west4-a
kubectl -n cockroachdb exec -it cockroachdb-0 -- cat /cockroach/cockroach-certs/ca.crt  > ${DATA}/ca.crt
kubectl -n cockroachdb get secrets cockroachdb.client.root -o jsonpath="{.data['cert']}" | base64 -d > ${DATA}/client.root.crt
kubectl -n cockroachdb get secrets cockroachdb.client.root -o jsonpath="{.data['key']}" | base64 -d > ${DATA}/client.root.key


echo "[*] fetching Ceph object store credentials"

gcloud container clusters get-credentials encryptonize-object --zone=europe-west4-a
kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_ACCESS_KEY_ID']}" | base64 -d > ${DATA}/object_storage_id
kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_SECRET_ACCESS_KEY']}" | base64 -d > ${DATA}/object_storage_key
kubectl -n rook-ceph get secret ingress-certificate -o jsonpath="{.data['tls\.crt']}" | base64 -d > ${DATA}/object_storage.crt

echo "[*] fetching Encryption Service certificate"

gcloud container clusters get-credentials encryptonize --zone=europe-west4-a
kubectl -n encryptonize get secret ingress-certificate -o jsonpath="{.data['tls\.crt']}" | base64 -d > ${DATA}/encryptonize.crt


echo "[*] setting up Docker credentials"

gcloud auth configure-docker eu.gcr.io --quiet
