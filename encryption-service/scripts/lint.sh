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

# Run gofmt and golanci-lint. Usage
#   ./scripts/lint.sh

set -euo pipefail

source ./scripts/build-env

echo "[*] formatting code"
gofmt -l -w .

echo "[*] tidying up"
go mod tidy

echo "[*] running linter"
golangci-lint run -E gosec,asciicheck,bodyclose,gocyclo,unconvert,gocognit,misspell,revive,whitespace -D unused --timeout 5m
