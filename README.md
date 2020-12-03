# Encryptonize&reg; Core

![es build](https://github.com/cyber-crypt-com/encryptonize-core/workflows/Encryption%20service%20build/badge.svg)
![es deploy](https://github.com/cyber-crypt-com/encryptonize-core/workflows/Encryption%20service%20deploy/badge.svg)

<img src="documentation/imgs/rook-hex.png" alt="Encryptonize" width="250"/>

# Encryptonize&reg; Core

Encryptonize&reg; Core is a secure cloud storage solution aimed at making it easy to manage sensitive
data across multiple cloud environments while simultaneously removing the need to trust the cloud
providers with encryption keys. Encryptonize&reg; provides an Encryption Service with a simple gRPC
interface that allows multiple workloads or users to store and retrieve data securely using cloud storage,
leveraging [Rook](https://rook.io/) with [Ceph](https://ceph.io/) and
[CockroachDB](https://www.cockroachlabs.com/product/) to ensure highly resilient storage.

Encryptonize&reg; is designed with the philosophy that you should not have to unconditionally trust cloud
providers to protect your sensitive data, and that having to manage keys and credentials across
several cloud environments is a security problem in itself. The Encryption Service minimizes the
potential attack surface and simplifies key management, while still allowing you to take advantage
of a multi cloud setup. It is designed to not only encrypt and authenticate your data using modern
cryptographic standards, but also to cryptographically enforce user authentication and
authorization.

## Achitecture overview

<img src="documentation/imgs/encryptonize-arch.png" alt="Encryptonize&reg;" width="100%"/>

At the core, Enryptonize&reg; consists of an Encryption Service (ES). In future releases of
Enryptonize&reg; a Key Service will be added to automatically handle distribution of key material to
Encryption Services. In the current iteration, key material is distributed manually by the deployer.
Please use best-practises for keeping the key material safe.

The default Kubernetes setup requires 3 clusters, but the setup can be modified to suit your needs.
The 3 clusters are:
- **Workload cluster** - this is where the ES is deployed and available for integration with a workload.
Note that we recommend that the data producer / consumer is deployed as close to the ES as possible, and
if a remote connection must be established, care must be taken to ensure safe transport to and from the
ES.
- **Auth cluster** - The cluster where the authentication and authorization state is saved. In a simple
setup with only 1 workload cluster, the services for the auth cluster could be deployed locally to that
same cluster. In the current setup, a Cockroach DB is installed and used.
- **Storage cluster** - The remote storage where the encrypted packages are stored. Note that any
associated data stored with the encrypted packaged is not encrypted and can be accessed as plain text.
In theory any S3 compatible storage can be used for the storage cluster. In our default setup we utilize
Rook to deploy Ceph.


# Running Encryptonize&reg; Core locally

The easiest way to try out Encryptonize&reg; is to start a local Docker Compose instance. To do
this, run
```
cd encryption-service
make docker-up
```
This will start a complete Encryptonize&reg; instance inside docker. To shut down the
Encryptonize&reg; instance, call
```bash
make docker-down
```
For more details, see the [Encryption Service README](encryption-service/README.md).


# Deploying Encryptonize&reg; Core

We supply Kubernetes files for deploying the full Encryptonize&reg; setup in a basic configuration.
The files can be found in the `kubernetes` folder. For instructions on how to deploy, see that
[deployment README](kubernetes/README.md)


# Repository overview

```
├── applications                # Contains a sample applications
├── documentation               # User documentation
│   ├── licenses                    # Third party licenses
│   ├── manuals                     # User manuals
│   └── api                         # API specifications
├── encryption-service          # Source files for the encryption service
├── .github
│   └── workflows                   # CI/CD files
├── kubernetes                  # Files for kubernetes deployment
│   ├── auth-storage                # Deployment files for the auth storage
│   ├── encryption-service          # Deployment files for the Encryption Service
│   ├── logging                     # Deployment files for logging
│   └── object-storage              # Deployment files for the object store
└── README.md                   # This file
```
