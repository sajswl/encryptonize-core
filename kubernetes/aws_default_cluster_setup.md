# AWS cluster quickstart
## Prerequisites
You will need `aws` and `eksctl` CLI tools in order to complete this guide. You can find more information on setting up `aws` [here](https://docs.aws.amazon.com/polly/latest/dg/setup-aws-cli.html) and setting up `eksctl` [here](https://docs.aws.amazon.com/eks/latest/userguide/getting-started-eksctl.html#install-eksctl).

## Setting up the cluster
Create a new cluster and connect to it using the commands below. Note that you might want to adjust the node type and
quantity to suite your needs. We propose the following defaults for the encryption-service, cockroachdb and ceph clusters respectively:

```bash
ES_CLUSTER_NAME=encryptonize
ES_NUM_NODES=2
ES_MACHINE_TYPE=t3.xlarge

CDB_CLUSTER_NAME=encryptonize-auth
CDB_NUM_NODES=3
CDB_MACHINE_TYPE=t3.xlarge

CEPH_CLUSTER_NAME=encryptonize-object
CEPH_NUM_NODES=3
CEPH_MACHINE_TYPE=r6gd.xlarge
```

Create a default encryption-service cluster:
```bash
eksctl create cluster \
  --name $ES_CLUSTER_NAME \
  --nodes $ES_NUM_NODES \
  --node-type $ES_MACHINE_TYPE \
  --region eu-west-1
```

You can connect `kubectl` to the new encryption-service cluster by running:
```bash
aws eks --region eu-west-1 update-kubeconfig --name $ES_CLUSTER_NAME 
```

Create a default CockroachDB cluster:
```bash
eksctl create cluster \
  --name $CDB_CLUSTER_NAME \
  --nodes $CDB_NUM_NODES \
  --node-type $CDB_MACHINE_TYPE \
  --region eu-west-1
```

You can connect `kubectl` to the new CockroachDB cluster by running:
```bash
aws eks --region eu-west-1 update-kubeconfig --name $CDB_CLUSTER_NAME
```

Create a default Ceph cluster:
```bash
eksctl create cluster \
  --name $CEPH_CLUSTER_NAME \
  --nodes $CEPH_NUM_NODES \
  --node-type $CEPH_MACHINE_TYPE \
  --region eu-west-1
```

You can connect `kubectl` to the new Ceph cluster by running:
```bash
aws eks --region eu-west-1 update-kubeconfig --name $CEPH_CLUSTER_NAME
```
