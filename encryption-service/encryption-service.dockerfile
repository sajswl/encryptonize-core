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

FROM golang:1.15-buster as build-env

WORKDIR /encryption-service

# Fetch dependencies
COPY go.mod go.sum /encryption-service/
RUN go mod download -x

# Generate protobuf
COPY app/app.proto /encryption-service/app/
COPY authz/access_object.proto /encryption-service/authz/
COPY authn/authn.proto /encryption-service/authn/
RUN apt-get update \
    && apt-get install -y protobuf-compiler \
    && go get google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc
RUN protoc --go-grpc_out=app --go_out=app app/app.proto \
    && protoc --go_out=authz authz/access_object.proto \
    && protoc --go-grpc_out=authn --go_out=authn authn/authn.proto

# Build dependencies
COPY . /encryption-service

# Build binary
ARG COMMIT
ARG TAG
ENV CGO_ENABLED=0
RUN go build -v -ldflags "-X 'encryption-service/app.GitCommit=$COMMIT' -X 'encryption-service/app.GitTag=$TAG'" -o /go/bin/es main.go

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

COPY --from=build-env /go/bin/es /
COPY --from=build-env /bin/grpc_health_probe /grpc_health_probe

USER 5000:5000

ENTRYPOINT ["/es"]
