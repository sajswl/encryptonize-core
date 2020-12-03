# Azure cluster quickstart
## Prerequisites
You will need the `az` CLI tool in order to complete this guide. You can find more information on setting up `az` [here](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli).

## Setting up the cluster
Create a new cluster and connect to it using the commands below. Note that you might want to adjust the node type and
quantity to suite your needs. We propose the following defaults for the encryption-service, cockroachdb and ceph clusters respectively:

```bash
ES_CLUSTER_NAME=encryptonize
ES_NUM_NODES=2
ES_MACHINE_TYPE=Standard_B4ms

CDB_CLUSTER_NAME=encryptonize-auth
CDB_NUM_NODES=3
CDB_MACHINE_TYPE=Standard_B8ms

CEPH_CLUSTER_NAME=encryptonize-object
CEPH_NUM_NODES=3
CEPH_MACHINE_TYPE=Standard_E4_v3
```

Create a resource group for your cluster:
```bash
az group create --name myResourceGroup --location westeurope
```

Create a default encryption-service cluster:
```bash
az aks create \
  --resource-group myResourceGroup \
  --name $ES_CLUSTER_NAME \
  --node-count $ES_NUM_NODES \
  --node-vm-size $ES_MACHINE_TYPE
  --generate-ssh-keys
```

You can connect `kubectl` to the new encryption-service cluster by running:
```bash
az aks get-credentials --resource-group myResourceGroup --name $ES_CLUSTER_NAME
```

Create a default CockroachDB cluster:
```bash
az aks create \
  --resource-group myResourceGroup \
  --name $CDB_CLUSTER_NAME \
  --node-count $CDB_NUM_NODES \
  --node-vm-size $CDB_MACHINE_TYPE
  --generate-ssh-keys
```

You can connect `kubectl` to the new CockroachDB cluster by running:
```bash
az aks get-credentials --resource-group myResourceGroup --name $CDB_CLUSTER_NAME
```

Create a default Ceph cluster:
```bash
az aks create \
  --resource-group myResourceGroup \
  --name $CEPH_CLUSTER_NAME \
  --node-count $CEPH_NUM_NODES \
  --node-vm-size $CEPH_MACHINE_TYPE
  --generate-ssh-keys
```

You can connect `kubectl` to the new Ceph cluster by running:
```bash
az aks get-credentials --resource-group myResourceGroup --name $CEPH_CLUSTER_NAME
```