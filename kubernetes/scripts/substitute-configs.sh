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
envsubst < encryptonize/kustomization.yaml.tmpl > encryptonize/kustomization.yaml
envsubst < rook-ceph/kustomization.yaml.tmpl > rook-ceph/kustomization.yaml
envsubst < rook-ceph/nginx.conf.tmpl > rook-ceph/nginx.conf
envsubst < logging/elastic/kustomization.yaml.tmpl > logging/elastic/kustomization.yaml
envsubst < logging/agents/kustomization.yaml.tmpl > logging/agents/kustomization.yaml
