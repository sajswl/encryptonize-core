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

FROM golang:1.15-buster as build-env

WORKDIR /encryption-service

# Build dependencies
COPY . /encryption-service
RUN apt-get update \
    && apt-get install -y protobuf-compiler \
    && go get google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc

# Build binary
ARG COMMIT
ARG TAG
ENV CGO_ENABLED=0
RUN make ldflags="-X 'encryption-service/services/app.GitCommit=$COMMIT' -X 'encryption-service/services/app.GitTag=$TAG'" build

# Adding the grpc_health_probe
RUN GRPC_HEALTH_PROBE_VERSION=v0.3.2 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe

##############################
### Runtime Image
FROM scratch

ARG COMMIT
ARG TAG
LABEL git-commit=${COMMIT}
LABEL git-tag=${TAG}

COPY --from=build-env /encryption-service/encryption-service /
COPY --from=build-env /bin/grpc_health_probe /grpc_health_probe

USER 5000:5000

ENTRYPOINT ["/encryption-service"]
