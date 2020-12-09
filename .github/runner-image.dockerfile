FROM ubuntu:20.04

# Skip apt-get dialogs during docker install
ENV DEBIAN_FRONTEND=noninteractive

# Dependencies
RUN apt-get update && \
  apt-get install -y wget curl git make python iproute2 && \
  rm -rf /var/lib/apt/lists/*

# go
RUN wget https://golang.org/dl/go1.15.6.linux-amd64.tar.gz && \
  tar -C /usr/local -xzf go1.15.6.linux-amd64.tar.gz && \
  rm -f go1.15.6.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
ENV PATH=$PATH:/root/go/bin

# Protobuf
RUN apt-get update && \
  apt-get install -y protobuf-compiler && \
  rm -rf /var/lib/apt/lists/*
RUN go get google.golang.org/protobuf/cmd/protoc-gen-go google.golang.org/grpc/cmd/protoc-gen-go-grpc && \
  rm -rf /root/.cache/*

# Docker
RUN curl -fsSL https://get.docker.com -o get-docker.sh && \
  sh get-docker.sh

# Docker compose
RUN curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/bin/docker-compose && \
  chmod +x /usr/bin/docker-compose

# GCloud
RUN curl https://sdk.cloud.google.com > install.sh && \
  bash install.sh --disable-prompts && \
  rm -rf /root/google-cloud-sdk/.install
RUN gcloud config set container/use_application_default_credentials true
ENV PATH=$PATH:/root/google-cloud-sdk/bin

# kubectl
RUN curl -L https://storage.googleapis.com/kubernetes-release/release/v1.19.4/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl && \
chmod +x /usr/local/bin/kubectl

# Tools
RUN curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.32.2
RUN go get github.com/wadey/gocovmerge && \
  rm -rf /root/.cache/*
RUN go get github.com/grpc-ecosystem/grpc-health-probe
