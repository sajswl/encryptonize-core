# Encryption Service

The Encryption Service is the user facing part of Encryptonize.

## Development Prerequisites

You will need the following tools:

* Go (version 1.15+) - [Install instructions](https://golang.org/doc/install)
* Protobuf compiler (version 3.12+) - [Install instructions](https://grpc.io/docs/protoc-installation/)
* Go plugin for protoc (version 1.26+) - [Install instructions](https://grpc.io/docs/languages/go/quickstart/#prerequisites)
* golangci-lint (version 1.33+) - [Install instructions](https://golangci-lint.run/usage/install/#local-installation)
* gocovmerge - `go get github.com/wadey/gocovmerge`
* Docker (version 19+) - [Install instructions](https://docs.docker.com/engine/install/)
* Docker Compose (version 2.0+)- [Install instructions](https://docs.docker.com/compose/install/)

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
This will generate an image with the tag `encryptonize`.

In order to run the Encryption Service locally, you have two options: standalone and Docker Compose.

### Standalone
A standalone instance of the Encryption Service can be started by calling
```bash
make run
```
This will expose the gRPC endpoints of Encryption Service on `localhost:9000`. To connect the
service to existing storage solutions you need to set the environment variables in [`scripts/run.sh`](scripts/run.sh).

To create an initial user run `make create-user`. The resulting user will have all possible scopes.

### Docker Compose
A self contained instance of Encryptonize can be started using Docker Compose. *Note that this setup
is only intended for test and development use.*

To start the Docker Compose setup, call
```bash
make docker-up
```
This will start local instances of CockroachDB and MinIO and connect a dockerized version of the
Encryption Service to these. To create an initial user run `make docker-create-user`. The resulting
user will have all possible scopes.

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

End-to-end tests can be run using one of the following targets
```bash
make e2e-tests-mem
make e2e-tests-docker
```

A coverage report for all tests can be generated using
```bash
make coverage
```

## The Encryption Service Configuration

By default the Encryption Service reads its configuration from the TOML file `config.toml`. This
behaviour can be modified by setting the environment variable `ECTNZ_CONFIGFILE`. The supported file
formats are TOML, YAML, and JSON.

All configuration options are documented in the example configuration
[`scripts/dev-config.toml`](sripts/dev-config.toml). All configuration options can be overwritten by
a corresponding environment variable. For example, the URL for the object storage can be overwritten
by setting `ECTNZ_OBJECTSTORAGE_URL`.

To modify the various `make` targets, modify the configuration in
[`scripts/dev-config.toml`](sripts/dev-config.toml). Note that for the docker-compose setup, some
options are overwritten by the `x-service-variables` in [`docker-compose.yml`](docker-compose.yml).
