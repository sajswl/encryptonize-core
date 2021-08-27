# GCP cluster quickstart
## Prerequisites
You will need the `gcloud` CLI tool in order to complete this guide. You can find more information on setting up `gcloud` [here](https://cloud.google.com/sdk/docs/install).

## Setting up the cluster
Create a new cluster and connect to it using the commands below. Note that you might want to adjust the node type and
quantity to suite your needs. We propose the following defaults for the encryption-service, cockroachdb and ceph clusters respectively:

```bash
ES_CLUSTER_NAME=encryptonize
ES_NUM_NODES=2
ES_MACHINE_TYPE=e2-standard-4

CDB_CLUSTER_NAME=encryptonize-auth
CDB_NUM_NODES=3
CDB_MACHINE_TYPE=e2-standard-4

CEPH_CLUSTER_NAME=encryptonize-object
CEPH_NUM_NODES=3
CEPH_MACHINE_TYPE=e2-highmem-4
```

Create a default encryption-service cluster:
```bash
gcloud container clusters create $ES_CLUSTER_NAME \
  --machine-type=$ES_MACHINE_TYPE \
  --num-nodes=$ES_NUM_NODES \
  --zone europe-west4-a \
  --logging=NONE
```

You can connect `kubectl` to the new encryption-service cluster by running:
```bash
gcloud container clusters get-credentials $ES_CLUSTER_NAME --zone=europe-west4-a
```

Create a default CockroachDB cluster:
```bash
gcloud container clusters create $CDB_CLUSTER_NAME \
  --machine-type=$CDB_MACHINE_TYPE \
  --num-nodes=$CDB_NUM_NODES \
  --zone europe-west4-a \
  --logging=NONE
```

You can connect `kubectl` to the new CockroachDB cluster by running:
```bash
gcloud container clusters get-credentials $CDB_CLUSTER_NAME --zone=europe-west4-a
```

Create a default Ceph cluster:
```bash
gcloud container clusters create $CEPH_CLUSTER_NAME \
  --machine-type=$CEPH_MACHINE_TYPE \
  --num-nodes=$CEPH_NUM_NODES \
  --zone europe-west4-a \
  --logging=NONE
```

You can connect `kubectl` to the new Ceph cluster by running:
```bash
gcloud container clusters get-credentials $CEPH_CLUSTER_NAME --zone=europe-west4-a
```
