FROM ubuntu:20.04

# Skip apt-get dialogs during docker install
ENV DEBIAN_FRONTEND=noninteractive

# Dependencies
RUN apt-get update && \
  apt-get install --no-install-recommends -y \
  ca-certificates wget curl git make gettext-base jq \
  python3 python3-crypto python3-pycryptodome \
  iproute2 build-essential clang openssh-client libmbedtls-dev && \
  rm -rf /var/lib/apt/lists/*

# GCloud
RUN curl https://sdk.cloud.google.com > install.sh && \
  bash install.sh --disable-prompts && \
  rm -rf /root/google-cloud-sdk/.install && \
  rm -f /root/google-cloud-sdk/bin/anthoscli && \
  rm -f /root/google-cloud-sdk/bin/kuberun
ENV PATH=$PATH:/root/google-cloud-sdk/bin
ENV CLOUDSDK_CONTAINER_USE_APPLICATION_DEFAULT_CREDENTIALS=true
RUN mkdir /root/.gcp
COPY deployer-staging.json /root/.gcp/deployer-staging.json

# go
RUN wget https://golang.org/dl/go1.17.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go1.17.linux-amd64.tar.gz && \
  rm -f go1.17.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
ENV PATH=$PATH:/root/go/bin

# Go tools
RUN apt-get update && \
  apt-get install --no-install-recommends -y protobuf-compiler && \
  rm -rf /var/lib/apt/lists/*
RUN go get google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc && \
  go get github.com/wadey/gocovmerge && \
  go get github.com/grpc-ecosystem/grpc-health-probe && \
  rm -rf /root/.cache/* && \
  rm -rf /root/go/src
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.42.1

# Docker
RUN curl -fsSL https://get.docker.com -o get-docker.sh && \
  sh get-docker.sh && \
  rm -f /usr/bin/containerd* && \
  rm -f /usr/bin/dockerd && \
  rm -rf /usr/libexec/docker

# Docker compose
RUN wget -O /usr/bin/docker-compose https://github.com/docker/compose/releases/download/v2.0.1/docker-compose-linux-x86_64 && \
  chmod +x /usr/bin/docker-compose

# kubectl
RUN curl -L https://storage.googleapis.com/kubernetes-release/release/v1.21.3/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl && \
  chmod +x /usr/local/bin/kubectl

# openjdk-11
RUN apt-get update && \
  apt-get update && apt-get install -y openjdk-11-jdk && \
  rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64
ENV PATH=$PATH:$JAVA_HOME/bin
