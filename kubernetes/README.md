# Deploying Encryptonize&reg;

Deploying Encryptonize&reg; consists of four main steps:
1. [Deploying a CockroachDB cluster](#cockroachdb-deployment)
2. [Deploying a Rook-Ceph cluster](#rook-ceph-deployment)
3. [Deploying the Encryption Service](#encryption-service-deployment)
4. [(Optional) Set up log aggregation](#log-aggregation-optional)

Make sure to follow the necessary steps in the [Prerequisites](#Prerequisites) section as well.

## Overview

### Encryption Service

The Encryption Service is a simple service that can be deployed locally or in the cloud. It is the
only point in the system where users are authenticated, access is authorized, and data is
encrypted/decrypted. The service is essentially stateless (aside from key material), and therefore
relies on two services for permanent storage, namely CockroachDB and Rook-Ceph.

### Storage

**CockroachDB** is a distributed SQL database built to be highly scalable and resilient to failures.
It is designed to be easy to deploy in multiple locations and across multiple clouds. Encryptonize
uses CockroachDB to store data used by the Encryption Service for authentication and authorization.

**Rook-Ceph** is a combination of the Kubernetes storage orchestrator Rook and the distributed
storage system Ceph. Ceph is a highly scalable and redundant storage solution which supports block,
file, and object storage. Rook makes it easy to deploy Ceph using Kubernetes, and helps to keep the
Ceph cluster healthy. Encryptonize uses Rook-Ceph as its object storage backend.

### Log Gathering

Since the system is distributed, the logging framework needs to handle scraping, processing,
delivering and viewing of logs in a distributed fashion. For this, we provide a Fluentbit /
Elasticsearch / Kibana stack.

**Fluentbit** is a lightweight log-scraping agent which scrapes, processes and delivers logs to a
specified environment. Fleuntbit is highly modular and comes with pre-built modules for scraping in
a Kubernetes environment, processing of Docker logs and outputting the logs to Elasticsearch. For
more information, see [fluentbit.io](https://fluentbit.io/).

**Elasticsearch** is an indexing platform. It can process, aggregate, store and retrieve logs.
Especially the retrieval process is highly optimized. For more information, see
[elastic.co/elasticsearch](https://www.elastic.co/elasticsearch/)

**Kibana** is part the Elastic family and lives on top of the Elasticsearch API. It provides an
interface to quickly view the logs, create log statistics and alerts. For more information, see
[elastic.co/kibana](https://www.elastic.co/kibana).

### TLS Certificates

TLS connections are used between all components of the Encryptonize system. As TLS certificate
provisioning in Kubernetes highly depends on the desired setup, the Kubernetes files provided here
use [cert-manager](https://cert-manager.io/) to provision self-signed certificates. For an serious
setup we recommend setting up certificates using e.g. [Let's Encrypt](https://letsencrypt.org/) or
your organizations own PKI.

## Prerequisites

### Cluster Provisioning
You will need to set up several clusters with your chosen cloud provider. We will use Google
Kubernetes Engine as a working example throughout, but only few steps are specific to this provider.
As such minimal changes are needed to set up Encryptonize with one or more other cloud providers.

* [Getting started with Amazon Elastic Kubernetes Service](https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html)
* [Getting started with Azure Kubernetes Service](https://docs.microsoft.com/en-us/azure/aks/kubernetes-walkthrough)
* [Getting started with Google Kubernetes Engine](https://cloud.google.com/kubernetes-engine/docs/quickstart)

### Hostname Setup
Independent of your choice of cloud provider you will need to set up [`kubectl`](https://kubernetes.io/docs/tasks/tools/install-kubectl/).

You will also need to allocate four hostnames with your DNS provider:
* A hostname for the Encryption Service, e.g. `encryptonize.example.com`.
* A hostname for the Rook-Ceph object store, e.g. `object.example.com`.
* A hostname for the CockroachDB database, e.g. `db.example.com`.
* (Optional) A hostname for Elasticsearch, e.g. `elasticsearch.example.com`.

### Kubernetes config substitution
In order to deploy the entire infrastructure, you will need to fill out the config in `kubernetes/scripts/deploy_env`. 

## CockroachDB Deployment

You need a Kubernetes cluster in order to deploy CockroachDB. If you don't have one, we provide a
quickstart guide to set one up:

1. [AWS cluster quickstart](aws_default_cluster_setup.md)
2. [Azure cluster quickstart](azure_default_cluster_setup.md)
3. [GCP cluster quickstart](gcp_default_cluster_setup.md)

Note that you might want to adjust the node type and quantity to suite your needs.
Our default recommendation is a 3-node cluster with 4 CPU's and 16GB of memory for each node.

*The remaining steps are provider agnostic.* First, create the cockroachdb namespace: 
```bash
kubectl apply -f cockroachdb/namespace.yaml
```

Then generate the certificates needed for Cockroachdb and create them as Kubernetes secrets:
```bash
mkdir certs
mkdir my-safe-directory
cockroach cert create-ca --certs-dir=certs --ca-key=my-safe-directory/ca.key
cockroach cert create-client root --certs-dir=certs --ca-key=my-safe-directory/ca.key
kubectl create secret generic cockroachdb.client.root --from-file=certs
cockroach cert create-node --certs-dir=certs --ca-key=my-safe-directory/ca.key localhost 127.0.0.1 cockroachdb-public cockroachdb-publidefault cockroachdb-public.default.svc.cluster.local *.cockroachdb *.cockroachdb.default *.cockroachdb.default.svc.cluster.local
kubectl create secret generic cockroachdb.node --from-file=certs
```

Having the certs in place, you can now deploy the Cockroachdb:
```bash
kubectl apply -k cockroachdb/
```

## Rook-Ceph Deployment
You need a Kubernetes cluster in order to deploy Ceph. If you don't have one,
we provide a quickstart guide to set one up:

1. [AWS cluster quickstart](aws_default_cluster_setup.md)
2. [Azure cluster quickstart](azure_default_cluster_setup.md)
3. [GCP cluster quickstart](gcp_default_cluster_setup.md)

Note that you might want to adjust the node type and quantity to suite your needs.
If you do so, make sure to adjust the container resource requests and limits in
`rook-ceph/cluster.yaml` and `rook-ceph/object.yaml` as well. Our default
recommendation is a 3-node cluster with 4 CPU's and 32GB of memory for each node.

*The remaining steps are provider agnostic.* Deploy the Ceph Object Store to your cluster by running
the following:
```bash
source ./scripts/deploy_env
./scripts/substitute-configs.sh
kubectl apply -k rook-ceph/
```

Wait for everything to finish. You should see three `rook-ceph-osd` pods eventually (takes about 5
minutes):
```bash
watch kubectl -n rook-ceph get pod
```

At last you have to apply the following patch in order to enable ceph audit logs:

```bash
kubectl patch deployment rook-ceph-rgw-encryptonize-store-a -n rook-ceph --patch "$(cat rook-ceph/rgw-patch.yaml)"
```

## Encryption Service Deployment

The following steps deploy a small cluster with two Encryption Service nodes behind an ingress.

### Fetch and Create Secrets

The Encryption Service cluster will need TLS certificates and other credentials to connect to
CockroachDB and Rook-Ceph clusters. Start by creating an `encryptonize-secrets` folder:
```bash
mkdir encryptonize-secrets
```

Connect `kubectl` to the Rook-Ceph cluster. The Object Store exposes a RADOS Gateway with an S3 API.
To obtain credentials for the object store, run:
```bash
kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_ACCESS_KEY_ID']}" | base64 -d > ./encryptonize-secrets/object_storage_id
kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_SECRET_ACCESS_KEY']}" | base64 -d > ./encryptonize-secrets/object_storage_key
kubectl -n rook-ceph get secret ingress-certificate -o jsonpath="{.data['tls\.crt']}" | base64 -d > ./encryptonize-secrets/object_storage.crt
```

Connect `kubectl` to the CockroachDB cluster and retrieve the CA certificate, client certificate, and client key:
```bash
kubectl -n cockroachdb exec -it cockroachdb-0 -c cockroachdb -- cat /cockroach/cockroach-certs/ca.crt > ./encryptonize-secrets/ca.crt
kubectl -n cockroachdb get secrets cockroachdb.client.root -o jsonpath='{.data.cert}' | base64 -d > ./encryptonize-secrets/client.root.crt
touch ./encryptonize-secrets/client.root.key && chmod 600 ./encryptonize-secrets/client.root.key
kubectl -n cockroachdb get secrets cockroachdb.client.root -o jsonpath='{.data.key}' | base64 -d > ./encryptonize-secrets/client.root.key
```

Create random 32 byte keys:
```bash
hexdump -n 32 -e '1/4 "%08X"' /dev/urandom > ./encryptonize-secrets/AEK
hexdump -n 32 -e '1/4 "%08X"' /dev/urandom > ./encryptonize-secrets/KEK
hexdump -n 32 -e '1/4 "%08X"' /dev/urandom > ./encryptonize-secrets/TEK
hexdump -n 32 -e '1/4 "%08X"' /dev/urandom > ./encryptonize-secrets/UEK
```

Finally, you need to define the Encryption Service configuration in `encryptonize/encryptonize-config.yaml`
using the secrets you created above as well as the Rook-Ceph and CockroachDB hostnames:
```bash
apiVersion: v1
kind: ConfigMap
metadata:
  name: encryptonize-config
  namespace: encryptonize
data:
  # Fill out the configuration below
  config: |
  ...
```
Note that the `generate_files.sh` script will also automatically create the configuration if the
secrets have been generated.

### Set hostnames

You will need to set up hostnames for the CockroachDB and Rook-Ceph clusters and point the
Encryption Server at them.

Connect to the CockroachDB cluster and retrieve the external IP of the `cockroachdb-public` service
(once provisioned) using the following command:
```bash
kubectl -n cockroachdb get svc cockroachdb-public -o jsonpath="{.status.loadBalancer.ingress[0].ip}"
```
Assign the IP to the CockrachDB hostname using your DNS provider.

Connect to the Rook-Ceph cluster and retrieve the external IP of the `ceph-ingress` service (once
provisioned) using the following command:
```bash
kubectl -n rook-ceph get svc ceph-ingress -o jsonpath="{.status.loadBalancer.ingress[0].ip}"
```
Assign the IP to the hostname you used during deployment of the cluster using your DNS provider.

### Initialize the Database

Using the CockroachDB CLI tool (see install instructions
[here](https://www.cockroachlabs.com/docs/stable/install-cockroachdb.html)), initialize the database:
```bash
HOSTNAME=<CockroachDB Hostname>
TLSOPTS="sslmode=verify-ca&sslrootcert=encryptonize-secrets/ca.crt&sslcert=encryptonize-secrets/client.root.crt&sslkey=encryptonize-secrets/client.root.key"
echo 'CREATE DATABASE IF NOT EXISTS auth;' | cockroach sql --url "postgresql://root@${HOSTNAME}:26257/?${TLSOPTS}"
cockroach sql --url "postgresql://root@${HOSTNAME}:26257/auth?${TLSOPTS}" < ../encryptonize/data/auth_storage_basic.sql
cockroach sql --url "postgresql://root@${HOSTNAME}:26257/auth?${TLSOPTS}" < ../encryptonize/data/auth_storage_extended.sql
```

### Set up the cluster
You need a Kubernetes cluster in order to deploy Encryptonize. If you don't have one,
we provide a quickstart guide to set one up:

1. [AWS cluster quickstart](aws_default_cluster_setup.md)
2. [Azure cluster quickstart](azure_default_cluster_setup.md)
3. [GCP cluster quickstart](gcp_default_cluster_setup.md)

Note that you might want to adjust the node type and quantity to suite your needs.
Our default recommendation is a 2-node cluster with 4 CPU's and 16B of memory for each node.

*The remaining steps are provider agnostic.* Set up the basic configuration:
```bash
kubectl apply -f encryptonize/encryptonize-config.yaml
```
Create a cluster secret for the Encryptonize files:
```bash
kubectl -n encryptonize create secret generic encryptonize-secrets \
  --from-file=./encryptonize-secrets/ca.crt \
  --from-file=./encryptonize-secrets/client.root.crt \
  --from-file=./encryptonize-secrets/client.root.key
```

### Deploy the service
Having filled out `scripts/deploy_env`, deploy the service with the following commands:
```bash
source scripts/deploy_env
./scripts/substitute-configs.sh
kubectl apply -k encryptonize/
```

Wait until everything has started:
```bash
watch kubectl -n encryptonize get all
```

You will need the ingress certificate to connect to the Encryption Service:
```bash
kubectl -n encryptonize get secret ingress-certificate -o jsonpath="{.data['tls\.crt']}" | base64 -d > ./encryptonize.crt
```

Get the external IP of the `encryptonize-ingress` service and assign it to a hostname using your DNS
provider:
```bash
kubectl -n encryptonize get svc encryptonize-ingress -o jsonpath="{.status.loadBalancer.ingress[0].ip}"
```

## Log Aggregation (Optional)

### Elasticsearch

You will need to set up Elasticsearch in one of the existing clusters (we recommend the CockroachDB
cluster). Elasticsearch is already defined as a part of `cockroachdb/kustomization.yaml` and will therefore
automatically be deployed when deploying the auth-storage. 

After deployment, wait for the `elasticsearch` and `kibana` pods to be "Ready":
```bash
watch kubectl -n elasticsearch get pod
```

Get the external IP of the `elasticsearch-es-http` service and assign it to a hostname using your
DNS provider:
```bash
kubectl -n elasticsearch get svc elasticsearch-es-http -o jsonpath="{.status.loadBalancer.ingress[0].ip}"
```

### Fluentbit

You will need to deploy fluentbit to each of the clusters that you want to monitor. Note that the kustomization
files are already configured to deploy fluentbit, but you need to do some certificate bootstrapping to 
enable Fluentbit connection to Elasticsearch. To do the bootstrapping fetch the Elasticsearch
certificates from the cluster where Elasticsearch is deployed:
```bash
kubectl -n elasticsearch get secrets elasticsearch-es-http-certs-public -o jsonpath="{.data['tls\.crt']}" | base64 -d > es.crt
kubectl -n elasticsearch get secrets elasticsearch-es-http-certs-public -o jsonpath="{.data['ca\.crt']}" | base64 -d > es-ca.crt
export PASSWORD=$(kubectl -n elasticsearch get secret elasticsearch-es-elastic-user -o go-template='{{.data.elastic | base64decode}}')
```

Then repeat the following steps in each cluster. First set up the configuration:
```bash
kubectl apply -f logging/agents/fluent-bit-rbac.yaml
kubectl -n fluentbit create secret generic elasticsearch-config --from-literal=password=$PASSWORD
kubectl -n fluentbit create secret generic elasticsearch-certs \
  --from-file=es.crt \
  --from-file=es-ca.crt
```

At last, restart the fluentbit agent:
```bash
kubectl -n fluentbit rollout restart ds/fluent-bit
```

### Accessing the Kibana UI

To access the Kibana UI, first connect to the cluster where you deploted Elasticsearch and then
port-forward the `kibana-kb-http` service:
```bash
kubectl -n elasticsearch port-forward service/kibana-kb-http 5601
```

Go to `https://localhost:5601` (accept the self signed certificate) and login using user `elastic`
and the password obtained from the related Kubernetes secret:
```bash
kubectl -n elasticsearch get secret elasticsearch-es-elastic-user -o go-template='{{.data.elastic | base64decode}}'
```

### Fluentbit Config
A few notes on the default configuration mainly from [the official documentation](https://docs.fluentbit.io/manual/administration/configuring-fluent-bit/configuration-file).
The main configuration file supports four types of sections:

* Service - Global settings for the Fluentbit agent
* Input - Configurations for the source of the logs
* Filter - Used to add, select or drop logging events
* Output - Configurations for the ouput destination of the logs

These are the main modules of the Fluentbit pipeline. Here is a highlight of some of our default
settings:
* Service.Flush = 2: Fluentbit will flush the logs to the output every 2 nanoseconds.
* Service.Log_Level = info: Refers to the logging of the Fluentbit service itself and will log at
  'info' level.
* Service.Daemon = off: Fluentbit should not run as a background process since it has it's own
  container.
* Input.Path: Is the path of the container logs located on the node. Wildcards are used to select
  encryptonize, ceph, CDB containers.
* Input.Parser = Docker: Since all our services are containerized, it is sensible to use the
  built-in Docker log parser.
* Input.Mem_Buf_Limit = 5MB: The ammount of log data Fluentbit can hold at a time. The total
  throughput is therefore a function of this number and Service.Flush.
* Filter.Name = es: We use kubernetes filters to enrich the logs with extra fields such as container
  and pod names. The filter is also configured with custom parsers for the object-store, auth-store
  and the encryption-service.
* Filter.Merge_Parser = <parser>: Selects a parser which will be used to parse the contents of the
  "log" field (which is the stdout of the service). If the parser cannot match the content, it will
  skip parsing and the "log" field is preserved as is. Otherwise, the "log" field is split up into
  several fields.
