# Encryption Service

The Encryption Service is the user facing part of Encryptonize.

## Development Prerequisites

You will need the following tools:

* Go (version 1.15+) - [Install instructions](https://golang.org/doc/install)
* Protobuf compiler (version 3.12+) - [Install instructions](https://grpc.io/docs/protoc-installation/)
* Go plugin for protoc (version 1.25+) - [Install instructions](https://grpc.io/docs/languages/go/quickstart/#prerequisites)
* golangci-lint (version 1.33+) - [Install instructions](https://golangci-lint.run/usage/install/#local-installation)
* gocovmerge - `go get github.com/wadey/gocovmerge`
* Docker (version 19+) - [Install instructions](https://docs.docker.com/engine/install/)
* Docker Compose (version 1.27+)- [Install instructions](https://docs.docker.com/compose/install/)
* gRPC health probe (version 0.3.4+) - [Install instructions](https://github.com/grpc-ecosystem/grpc-health-probe)

Additionally you need to add `$(go env GOPATH)/bin` to your `PATH`, i.e. by adding
```bash
export PATH=$PATH:$(go env GOPATH)/bin
```
or similar to your shell. For deployment to GKE clusters you will also need:
* GCloud - [Install instructions](https://cloud.google.com/sdk/docs/install)
* kubectl - [Install instructions](https://kubernetes.io/docs/tasks/tools/install-kubectl/)


## Building and running locally
You can build the Encryption Service by running:
```bash
make build
```

You can build the Encryption Service docker image by running:
```bash
make docker-build
```
This wil generate an image with the tag `encryptonize`.

In order to run the Encryption Service locally, you have two options: standalone and Docker Compose.

### Standalone
A standalone instance of the Encryption Service can be started by calling
```bash
make run
```
This will expose the gRPC endpoints of Encryption Service on `localhost:9000`. To connect the
service to existing storage solutions you need to set the environment variables in [`scripts/run.sh`](scripts/run.sh).


### Docker Compose
A selfcontained instance of Encryptonize can be started using Docker Compose. *Note that this setup
is only intended for test and development use.*

To start the Docker Compose setup, call
```bash
make docker-up
```
This will start local instances of CockroachDB and MinIO and connect a dockerized version of the
Encryption Service to these. An admin user with the following credentials will automatically be
created:
```
User ID: 00000000-0000-4000-8000-000000000002
Access Token: 0000000000000000000000000000000000000000000000000000000000000002
```
The gRPC endpoints of the Encryption Service are exposed on `localhost:9000`. MinIO's web console is
exposed on `localhost:7000` (ID `storageid` and key `storagekey`) while CockroachDB's web console is
exposed on `localhost:7001`.

When you are done with the service, stop it again by calling
```bash
make docker-down
```
Note that when using `make docker-down` data is not persisted. To keep data after shutting down the
instance, manually call `docker-compose down`.  The setup can be tweaked by modifying the settings
in `docker-compose.yml`.

## Running tests
Various levels of tests are available. In order to run static checks, call
```bash
make lint
```

Unit tests can be run with
```bash
make unit-tests
```

After starting a standalone instance or a Docker Compose instance, end-to-end tests can be run using
```bash
make e2e-tests
```

A coverage report for all tests can be generated using
```bash
make coverage
```

## The Encryption Service Environment

The Encryption Service uses various environment variables to modify its behavior. The current environment variables are listed below:

| Name                | Description                           |
| ------------------- | ------------------------------------- |
| KEK                 | Key material as a 64 digit hex string |
| ASK                 | Key material as a 64 digit hex string |
| AUTH_STORAGE_URL    | Connection URL for the auth storage   |
| OBJECT_STORAGE_URL  | Connection URL for the object store   |
| OBJECT_STORAGE_ID   | Key ID for the object store           |
| OBJECT_STORAGE_KEY  | Secret key for the object store       |
| OBJECT_STORAGE_CERT | Certificate for the object store      |

To modify the various `make` targets, set these environment variables in the relevant scripts in
[`scripts`](scripts) (see e.g. [`scripts/run.sh`](scripts/run.sh). To modify the docker-compose setup, set the
`x-service-variables` in [`docker-compose.yml`](docker-compose.yml).
