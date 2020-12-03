# Rook-ceph Object Storage Setup
This folder contains Kubernetes files that can be used to deploy a Ceph Object Store using Rook. For
more details, see the [Rook documentation](https://rook.io/docs/rook/v1.4/ceph-storage.html).

## Create a cluster
The instructions here assume deployment to a Google Kubernetes Engine cluster, but minimal changes
are required to the Kubernetes files in order to deploy to a different cloud provider.

Follow the instructions [here](https://cloud.google.com/kubernetes-engine/docs/quickstart) to enable
the GKE API for your project. Then, to create a cluster suitable for the specified object store,
run:
```bash
gcloud container clusters create encryptonize-object \
  --disk-type=pd-ssd \
  --machine-type=e2-highmem-4 \
  --num-nodes=3 \
  --zone europe-west4-a
```

You need to configure `kubectl` to access your cluster. See instructions
[here](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl).

## Deploy the Object Store
To deploy the Ceph Object Store, run the following:
```bash
kubectl apply -f crds.yaml -f common.yaml -f operator.yaml
kubectl apply -f cluster.yaml
kubectl apply -f object.yaml
```

Wait for everything to finish. You should see three `rook-ceph-osd` pods eventually (takes about 5
minutes):
```bash
watch kubectl -n rook-ceph get all
```
You also need to wait for the `encryptonize-store` service to provision an IP:
```bash
watch kubectl -n rook-ceph get svc encryptonize-store
```

## Extract S3 Credentials
The Object Store exposes a RADOS Gateway with an S3 API. To obtain credentials for the object store,
run:
```bash
export AWS_HOST=$(kubectl -n rook-ceph get svc encryptonize-store -o jsonpath="{.status.loadBalancer.ingress[0].ip}")
export AWS_ACCESS_KEY_ID=$(kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_ACCESS_KEY_ID']}" | base64 -d)
export AWS_SECRET_ACCESS_KEY=$(kubectl -n rook-ceph get secret bucket-claim -o jsonpath="{.data['AWS_SECRET_ACCESS_KEY']}" | base64 -d)
```

## Using the Object Store
You can directly access the RADOS Gateway using `s3cmd`. See install instructions
[here](https://github.com/s3tools/s3cmd). To run S3 commands:
```bash
s3cmd --no-ssl --host-bucket= --host=$AWS_HOST [command]
```

For example, get the bucket name:
```bash
s3cmd --no-ssl --host-bucket= --host=$AWS_HOST ls
```

Push a file to it:
```bash
echo "Hello, world!" > hello.txt
s3cmd --no-ssl --host-bucket= --host=$AWS_HOST put ./hello.txt s3://objects
```

Retrieve it again:
```bash
s3cmd --no-ssl --host-bucket= --host=$AWS_HOST get s3://objects/hello.txt hello.txt.dl
```

## Port forwarding
The above setup does not have a TLS ingress configured. To achieve confidentiality without setting
up an ingress, you can chose to port-forward the ceph service to your local machine:

`kubectl port-forward service/rook-ceph-rgw-my-store 8080:80 -n rook-ceph`

Then, ceph is accesible from within the localhost on port 8080. For example:

`s3cmd --no-ssl --host-bucket= --host=127.0.0.1:8080 ls`
