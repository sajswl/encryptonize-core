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
# Generate CockroachDB certficates

set -euo pipefail

RED_ON="\u1b[1;31m"
BLUE_ON="\u1b[1;34m"
COLOR_OFF="\u1b[m"

ROOT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && cd .. && pwd )"

# Generate CockroachDB certificates
AUTH_OUT_FOLDER="${ROOT_DIR}/auth/bootstrap/config"

if [[ -d "$AUTH_OUT_FOLDER" ]]; then
  echo -e "${RED_ON}[+] Refusing to overwrite CockroachDB certificates!"
  echo -e "[-] Manually delete the folder '${AUTH_OUT_FOLDER}' to generate new certificates.${COLOR_OFF}"
else
  echo -e "${BLUE_ON}[+] Generating CockroachDB certificates${COLOR_OFF}"
  mkdir -p "$AUTH_OUT_FOLDER"

  cockroach cert create-ca \
    --certs-dir="${AUTH_OUT_FOLDER}" \
    --ca-key="${AUTH_OUT_FOLDER}/cockroach.ca.key"
  cockroach cert create-client \
    root \
    --certs-dir="${AUTH_OUT_FOLDER}" \
    --ca-key="${AUTH_OUT_FOLDER}/cockroach.ca.key"
  cockroach cert create-client \
    encryptonize \
    --certs-dir="${AUTH_OUT_FOLDER}" \
    --ca-key="${AUTH_OUT_FOLDER}/cockroach.ca.key"
  cockroach cert create-node \
    localhost 127.0.0.1 \
    cockroachdb-public \
    cockroachdb-public.cockroachdb \
    cockroachdb-public.cockroachdb.svc.cluster.local \
    *.cockroachdb \
    *.cockroachdb.cockroachdb \
    *.cockroachdb.cockroachdb.svc.cluster.local \
    --certs-dir="${AUTH_OUT_FOLDER}" \
    --ca-key="${AUTH_OUT_FOLDER}/cockroach.ca.key"
fi

# Generate object store certificates
OBJ_OUT_FOLDER="${ROOT_DIR}/object/bootstrap/config"

if [[ -d "$OBJ_OUT_FOLDER" ]]; then
  echo -e "${RED_ON}[+] Refusing to overwrite object storage certificates!"
  echo -e "[-] Manually delete the folder '${OBJ_OUT_FOLDER}' to generate new certificates.${COLOR_OFF}"
else
  mkdir -p "${OBJ_OUT_FOLDER}"

  openssl req -new -x509 -days 365 -nodes \
    -subj "/CN=${OBJECT_STORAGE_HOSTNAME}" \
    -addext "subjectAltName = DNS:${OBJECT_STORAGE_HOSTNAME}" \
    -out "${OBJ_OUT_FOLDER}/object_storage.crt" \
    -newkey ED25519 \
    -keyout "${OBJ_OUT_FOLDER}/object_storage.key"
fi

# Generate Encryptonize encryption keys
ENC_OUT_FOLDER="${ROOT_DIR}/encryptonize/bootstrap/config"

if [[ -d "$ENC_OUT_FOLDER" ]]; then
  echo -e "${RED_ON}[+] Refusing to overwrite Encryptonize keys!"
  echo -e "[-] Manually delete the folder '${ENC_OUT_FOLDER}' to generate new keys.${COLOR_OFF}"
else
  echo -e "${BLUE_ON}[+] Generating Encryptonize keys${COLOR_OFF}"
  mkdir -p "$ENC_OUT_FOLDER"

  ECTNZ_KEYS_KEK=$(hexdump -n 32 -e '1/4 "%08x"' /dev/urandom)
  ECTNZ_KEYS_AEK=$(hexdump -n 32 -e '1/4 "%08x"' /dev/urandom)
  ECTNZ_KEYS_TEK=$(hexdump -n 32 -e '1/4 "%08x"' /dev/urandom)
  ECTNZ_KEYS_UEK=$(hexdump -n 32 -e '1/4 "%08x"' /dev/urandom)
  ECTNZ_KEYS_GEK=$(hexdump -n 32 -e '1/4 "%08x"' /dev/urandom)

  {
    echo "ECTNZ_KEYS_KEK=${ECTNZ_KEYS_KEK}"
    echo "ECTNZ_KEYS_AEK=${ECTNZ_KEYS_AEK}"
    echo "ECTNZ_KEYS_TEK=${ECTNZ_KEYS_TEK}"
    echo "ECTNZ_KEYS_UEK=${ECTNZ_KEYS_UEK}"
    echo "ECTNZ_KEYS_GEK=${ECTNZ_KEYS_GEK}"
  } > "${ENC_OUT_FOLDER}/keys.env"

  echo -e "${BLUE_ON}[+] Moving over CockroachDB client certificates${COLOR_OFF}"
  mv "${AUTH_OUT_FOLDER}/client.encryptonize.crt" "${ENC_OUT_FOLDER}"
  mv "${AUTH_OUT_FOLDER}/client.encryptonize.key" "${ENC_OUT_FOLDER}"
  cp "${AUTH_OUT_FOLDER}/ca.crt" "${ENC_OUT_FOLDER}"
fi
