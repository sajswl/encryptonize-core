# Encryptonize® Core

<img alt="Encryptonize" src="https://raw.githubusercontent.com/cyber-crypt-com/encryptonize-core/master/documentation/imgs/rook-hex.png" width="250">

Encryptonize® Core is a secure cloud storage solution aimed at making it easy to manage sensitive
data across multiple cloud environments while simultaneously removing the need to trust the cloud
providers with encryption keys. Encryptonize® provides an Encryption Service with a simple gRPC
interface that allows multiple workloads or users to store and retrieve data securely using cloud storage,
leveraging S3 compatible storage like [Rook](https://rook.io/) with [Ceph](https://ceph.io/) and
a PostgreSQL compatible database.

## How to Use This Image
The following Docker Compose file illustrates how to setup an example Encryptonize® deployment.
It uses [MinIO](https://min.io/) as its object store and [PostgreSQL](https://www.postgresql.org/) for auth storage.

**Warning**: The example just illustrates a quick way for trying out Encryptonize® and is not meant for any production usage!
It's not secure (especially the provided test key material) and doesn't keep any data if the containers are removed.

For a detailed manual on how to securely deploy Encryptonize® check out [the deployment README](https://github.com/cyber-crypt-com/encryptonize-core/blob/master/kubernetes/README.md).

```
TODO: insert docker-compose.yml here
```

### Start Encryptonize® Deployment 

`docker-compose  up`

### Create an Initial Admin User

`docker-compose run encryption-service create-admin`

Note down the generated admin credentials: `User ID`, `Password`


### Usage Example
The following example script shows the basic use cases for Encryptonize®.

Dependencies:
 - [gRPCurl](https://github.com/fullstorydev/grpcurl)
 - [jq](https://stedolan.github.io/jq/)

Please fill in the generated admin credentials from the previous step.

```
TODO: insert example.sh here
```

# License

Use of Encryptonize®  is governed by the Apache 2.0 License found at [LICENSE](https://github.com/cyber-crypt-com/encryptonize-core/blob/master/LICENSE).
