# Encryptonize® Core

<img alt="Encryptonize" src="https://raw.githubusercontent.com/cyber-crypt-com/encryptonize-core/master/documentation/imgs/rook-hex.png" width="250">

Encryptonize® Core is a secure cloud storage solution aimed at making it easy to manage sensitive
data across multiple cloud environments while simultaneously removing the need to trust the cloud
providers with encryption keys. Encryptonize® provides an Encryption Service with a simple gRPC
interface that allows multiple workloads or users to store and retrieve data securely using cloud storage,
leveraging S3 compatible storage like [Rook](https://rook.io/) with [Ceph](https://ceph.io/) and
a PostgreSQL compatible database storage.

## How to Use This Image
The following Docker Compose file illustrates how to setup an example Encryptonize® deployment.
It uses [MinIO](https://min.io/) as its objects store and [PostgreSQL](https://www.postgresql.org/) for auth storage.

**Warning**: The example just illustrates a quick way for trying out Encryptonize® and it not meant for any production usage!
It's not secure (especially the provided test key material) and doesn't keep any data if the containers are removed.

For a detailed manual how to securely deploy Encryptonize® check out [the deployment README](https://github.com/cyber-crypt-com/encryptonize-core/blob/master/kubernetes/README.md).

```
version: "3.8"

x-service-variables: &service-variables
  ECTNZ_SERVICE_INSECURE: "1"
  ECTNZ_KEYS_KEK: "0000000000000000000000000000000000000000000000000000000000000000"
  ECTNZ_KEYS_ASK: "0000000000000000000000000000000000000000000000000000000000000001"
  ECTNZ_KEYS_TEK: "0000000000000000000000000000000000000000000000000000000000000002"
  ECTNZ_KEYS_UEK: "0000000000000000000000000000000000000000000000000000000000000003"

  ECTNZ_AUTHSTORAGE_URL: "postgresql://postgres:password@auth-storage/postgres"
  ECTNZ_AUTHSTORAGE_SCHEMA: "/data/auth_storage_basic.sql"

  ECTNZ_OBJECTSTORAGE_URL: "http://object-storage:9000"
  ECTNZ_OBJECTSTORAGE_ID: &storage_id "storageid"
  ECTNZ_OBJECTSTORAGE_KEY: &storage_key "storagekey"
  # This is just a dummy certificate
  ECTNZ_OBJECTSTORAGE_CERT: |
    -----BEGIN CERTIFICATE-----
    MIIBpjCCAVigAwIBAgIUQ3byU/Dxv0eA11bPDYVC4xD36dwwBQYDK2VwMGUxCzAJBgNVBAYTAkRLMQowCAYDVQQIDAEuMQowCAYDVQQHDAEuMQwwCgYDVQQKDANmb28xGjAYBgkqhkiG9w0BCQEWC2Zvb0BiYXIuY29tMRQwEgYDVQQDDAtmb28uYmFyLmNvbTAeFw0yMDExMTgxNjM5MDVaFw0yMTExMTgxNjM5MDVaMGUxCzAJBgNVBAYTAkRLMQowCAYDVQQIDAEuMQowCAYDVQQHDAEuMQwwCgYDVQQKDANmb28xGjAYBgkqhkiG9w0BCQEWC2Zvb0BiYXIuY29tMRQwEgYDVQQDDAtmb28uYmFyLmNvbTAqMAUGAytlcAMhAEeBiCvHWsxIRPH6tSqmalACa4ckUhXGLoqFUSLef5jyoxowGDAWBgNVHREEDzANggtmb28uYmFyLmNvbTAFBgMrZXADQQAdA1YAoyBCqsFlePrYO6AP1eUgYfCKEjRUttIeSltIv+M+AEzZIU8+JB3nH684qyi8y7XwWuZVC64639WbLxoL
    -----END CERTIFICATE-----

services:
  encryption-service:
    image: brunocc/enc-core:v5
    environment:
      <<: *service-variables
    ports:
      - 9000:9000
    depends_on:
      - auth-storage
      - object-storage
    tty: true

  auth-storage:
    image: postgres:13
    environment:
      POSTGRES_PASSWORD: password

  object-storage:
    image: minio/minio
    environment:
      MINIO_ACCESS_KEY: *storage_id
      MINIO_SECRET_KEY: *storage_key
    command: server /data

  object-storage-init:
    image: minio/mc
    environment:
      MINIO_ACCESS_KEY: *storage_id
      MINIO_SECRET_KEY: *storage_key
    entrypoint: |
      /bin/sh -c "
        sleep 5
        /usr/bin/mc config host add --api s3v4 storage http://object-storage:9000 $${MINIO_ACCESS_KEY} $${MINIO_SECRET_KEY};
        /usr/bin/mc mb storage/objects/;
        /usr/bin/mc policy set public storage/objects"
    depends_on:
      - object-storage

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

```bash
# admin credentials -- From: Create an Initial Admin User
ADMIN_USER_ID='FILL_ME_IN'
ADMIN_PASSWORD='FILL_ME_IN'

# login as admin user
echo '[+] login admin user'
OUTPUT=$(grpcurl -plaintext \
  -d "{\"userId\": \"${ADMIN_USER_ID}\", \"password\": \"${ADMIN_PASSWORD}\"}" \
  localhost:9000 authn.Encryptonize.LoginUser)
echo "output: $OUTPUT"
echo "-------------------------------------"
export ADMIN_ACCESS_TOKEN=$(jq -r '.accessToken' <<< "${OUTPUT}")


# create a regular user
echo '[+] create regular user'
OUTPUT=$(grpcurl -plaintext \
  -H "authorization:bearer ${ADMIN_ACCESS_TOKEN}" \
  -d '{"userScopes": ["READ", "CREATE", "INDEX", "OBJECTPERMISSIONS", "USERMANAGEMENT"]}' \
  localhost:9000 authn.Encryptonize.CreateUser)
echo "output: $OUTPUT"
echo "-------------------------------------"
export USER_ID=$(jq -r '.userId' <<< "${OUTPUT}")
export PASSWORD=$(jq -r '.password' <<< "${OUTPUT}")


# login as regular user
echo '[+] login regular user'
OUTPUT=$(grpcurl -plaintext \
  -d "{\"userId\": \"${USER_ID}\", \"password\": \"${PASSWORD}\"}" \
  localhost:9000 authn.Encryptonize.LoginUser)
echo "output: $OUTPUT"
echo "-------------------------------------"
export ACCESS_TOKEN=$(jq -r '.accessToken' <<< "${OUTPUT}")


# store data
export PLAINTEXT=$(echo 'plaintext data to be stored' | base64)
export ASSOCIATED_DATA=$(echo 'associated data to be stored' | base64)

echo '[+] storing data'
OUTPUT=$(grpcurl -plaintext \
  -H "authorization:bearer ${ACCESS_TOKEN}" \
  -d "{\"object\": {\"plaintext\": \"${PLAINTEXT}\", \"associatedData\": \"${ASSOCIATED_DATA}\"}}" \
  localhost:9000 enc.Encryptonize.Store)
echo "output: $OUTPUT"
echo "-------------------------------------"
export OBJECT_ID=$(jq -r '.objectId' <<< "${OUTPUT}")


# retrieve data
echo '[+] retrieving data'
OUTPUT=$(grpcurl -plaintext \
  -H "authorization:bearer ${ACCESS_TOKEN}" \
  -d "{\"objectId\": \"${OBJECT_ID}\"}" \
  localhost:9000 enc.Encryptonize.Retrieve)
echo "output: $OUTPUT"

export RETRIEVED_PLAINTEXT=$(jq -r '.object.plaintext' <<< "${OUTPUT}")
export RETRIEVED_ASSOCIATED_DATA=$(jq -r '.object.associatedData' <<< "${OUTPUT}")

echo "plaintext: $(echo $RETRIEVED_PLAINTEXT| base64 -d)"
echo "associated data: $(echo $RETRIEVED_ASSOCIATED_DATA| base64 -d)"

```

# License

Use of Encryptonize®  is governed by the Apache 2.0 License found at [LICENSE](https://github.com/cyber-crypt-com/encryptonize-core/blob/master/LICENSE).
