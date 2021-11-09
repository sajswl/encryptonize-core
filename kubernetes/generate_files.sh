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

# Substitutes necessary variables in Encryptonize kubernetes files. Set the environment variables
# below to the desired values and run
#
#   ./generate_files.sh
#
# The files will be places in `./generated_files`.

#### Variables to set ####

export STORAGE_CLASS=standard
export OBJECT_STORAGE_HOSTNAME=object.example.com
export AUTH_STORAGE_HOSTNAME=db.example.com
export ENCRYPTION_SERVICE_HOSTNAME=encryptonize.example.com
export ELASTICSEARCH_HOSTNAME=elasticsearch.example.com
export ENCRYPTION_SERVICE_IMAGE=cybercryptcom/encryptonize-core:v3.1.0
export SECRETS_PATH=./encryptonize-secrets

##########################

FILE_DIR=./generated_files
mkdir -p ${FILE_DIR}/rook-ceph
mkdir -p ${FILE_DIR}/encryptonize
mkdir -p ${FILE_DIR}/logging

echo "Generating files in '${FILE_DIR}'"

envsubst '$STORAGE_CLASS' \
  < ./rook-ceph/cluster.yaml \
  > ${FILE_DIR}/rook-ceph/cluster.yaml
envsubst '$OBJECT_STORAGE_HOSTNAME' \
  < ./rook-ceph/ingress.yaml \
  > ${FILE_DIR}/rook-ceph/ingress.yaml
envsubst '$ENCRYPTION_SERVICE_HOSTNAME' \
  < ./encryptonize/encryptonize-ingress.yaml \
  > ${FILE_DIR}/encryptonize/encryptonize-ingress.yaml
envsubst '$ENCRYPTION_SERVICE_IMAGE' \
  < ./encryptonize/encryptonize-service.yaml \
  > ${FILE_DIR}/encryptonize/encryptonize-service.yaml
envsubst '$ELASTICSEARCH_HOSTNAME' \
  < ./logging/elastic-search.yaml \
  > ${FILE_DIR}/logging/elastic-search.yaml
envsubst '$ELASTICSEARCH_HOSTNAME' \
  < ./logging/fluent-bit-deploy.yaml \
  > ${FILE_DIR}/logging/fluent-bit-deploy.yaml

# Generate encryptonize-config.yaml if secrets have been generated
if [ -d "$SECRETS_PATH" ]; then
  echo "Generating configuration from secrets in '${SECRETS_PATH}'"
  export KEK=$(cat ${SECRETS_PATH}/KEK)
  export AEK=$(cat ${SECRETS_PATH}/AEK)
  export TEK=$(cat ${SECRETS_PATH}/TEK)
  export UEK=$(cat ${SECRETS_PATH}/UEK)
  export GEK=$(cat ${SECRETS_PATH}/GEK)
  export OBJECT_STORAGE_ID=$(cat ${SECRETS_PATH}/object_storage_id)
  export OBJECT_STORAGE_KEY=$(cat ${SECRETS_PATH}/object_storage_key)
  # Indent lines of cert to match yaml, skipping the first line
  export OBJECT_STORAGE_CERT=$(cat ${SECRETS_PATH}/object_storage.crt | sed -e '2,$s/^/    /')

  envsubst '$KEK $AEK $TEK $UEK $GEK $AUTH_STORAGE_HOSTNAME $OBJECT_STORAGE_HOSTNAME $OBJECT_STORAGE_ID $OBJECT_STORAGE_KEY $OBJECT_STORAGE_CERT' \
    < ./encryptonize/encryptonize-config.yaml \
    > ${FILE_DIR}/encryptonize/encryptonize-config.yaml
else
  echo "'${SECRETS_PATH}' not found, skipping configuration"
fi
