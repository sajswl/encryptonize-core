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

OUT_FOLDER=cockroachdb/certs

cockroach cert create-ca \
  --certs-dir="${OUT_FOLDER}" \
  --ca-key="${OUT_FOLDER}/cockroach.ca.key"
cockroach cert create-client \
  root \
  --certs-dir="${OUT_FOLDER}" \
  --ca-key="${OUT_FOLDER}/cockroach.ca.key"
cockroach cert create-client \
  encryptonize \
  --certs-dir="${OUT_FOLDER}" \
  --ca-key="${OUT_FOLDER}/cockroach.ca.key"
cockroach cert create-node \
  localhost 127.0.0.1 \
  cockroachdb-public \
  cockroachdb-public.cockroachdb \
  cockroachdb-public.cockroachdb.svc.cluster.local \
  *.cockroachdb \
  *.cockroachdb.cockroachdb \
  *.cockroachdb.cockroachdb.svc.cluster.local \
  --certs-dir="${OUT_FOLDER}" \
  --ca-key="${OUT_FOLDER}/cockroach.ca.key"
