# License
Copyright 2021 CYBERCRYPT

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

# Overview
This user manual is updated to correspond to version 3.1.0 of the API.

This document will provide a quick introduction on how to use the Encryptonize service and introduce
essential concepts and terminology. For a detailed description of the gRPC API, see [the
specification](../api/api-v3.1.0.md).

1. [Terminology](#terminology)
1. [Encryptonize configs](#encryptonize-configs)
1. [Authentication](#authentication)
1. [Users](#users)
    1. [Managing Users](#managing-users)
        1. [Bootstrapping users](#bootstrapping-users)
        1. [Generating users through API](#generating-users-through-api)
        1. [User Login](#user-login)
        1. [Remove User](#remove-user)
1. [Storage](#storage)
    1. [Storing data](#storing-data)
    1. [Retrieving data](#retrieving-data)
    1. [Updating data](#updating-data)
    1. [Deleting data](#deleting-data)
1. [Storage-less encryption](#storage-less-encryption)
    1. [Encryption](#encryption)
    1. [Decryption](#decryption)
1. [Permissions](#permissions)
    1. [Get permissions of an object](#get-permissions-of-an-object)
    1. [Add permissions to an object](#add-permissions-to-an-object)
    1. [Remove permissions from an object](#get-version-information)
1. [Version](#version)

# Terminology
Terminology specific to the Encryptonize service is introduced when needed. Every term will be
marked in **bold**. Value types are called by their protobuf name. For an overview of these names
translated to supported languages see this
[list](https://developers.google.com/protocol-buffers/docs/proto3#scalar).

# Encryptonize configs
By default the Encryption Service reads its configuration from the TOML file `config.toml`. This
behaviour can be modified by setting the environment variable `ECTNZ_CONFIGFILE`. The supported file
formats are TOML, YAML, and JSON.

All configuration options are documented in the example configuration
[`encryption-service/scripts/dev-config.toml`](../../encryption-service/sripts/dev-config.toml). 
All configuration options can be overwritten by a corresponding environment variable. For example, 
the URL for the object storage can be overwritten by setting `ECTNZ_OBJECTSTORAGE_URL`.

The configuration is divided in 4 sections. Each section is briefly described below.

## Keys configs
Keys are used by Encryptonize to secure confidentiality and integrity of the data. Therefore make sure 
that these are generated securely and randomly. The data cannot be accessed without the keys, so make 
sure to have a proper backup. 

## Auth storage configs
Auth storage contains user authorization data. Auth storage can be any database which supports Postgresql.
Encryptonize needs the host, port and credentials of the database in order to establish connections. 

## Feature flags configs
These flags can be used to toggle different features of Encryptonize.

## Object storage configs
Object storage contains all the encrypted data. Anything that supports the [S3 protocol](https://docs.aws.amazon.com/s3/index.html) 
can be used as object storage. Encryptonize needs to be configured with the URL, credentials and 
certificate for the object storage.

# Authentication
All authentication on the Encryptonize service is done via an `authorization` pair in gRPC metadata. 
It should contain the user access token and be in the form `bearer <user access token>`. 
A correct authentication metadata query could look like this:
```
{
  "authorization": "bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
}
```
This token is obtained upon user login as described in the [User Login section](#user-login). 
Note that the access token is short lived (1 hour).

# Users
A **user** is an authorization entity on the encryption server, and is only represented by a user ID.
The user ID is used to identify a single user. Each user has a password which can be used to obtain an
access token for authentication and authorization. An **object** is a cryptographically signed package 
containing the stored ciphertext and the associated data. A user can share stored data with other users
by modifying the permissions on an object. Instructions on how to share data between users can be found 
in the section on [*Permissions*](#permissions). The user that creates an object automatically has 
permission to acccess that object, and any user that can access an object can modify the permissions.

It should be noted that while the access tokens and passwords should be kept secret, user IDs can be considered
public information and safely shared between parties.

All IDs are of the format version 4 UUID ([RFC 4122](https://tools.ietf.org/html/rfc4122) section 4.4).

## Managing Users
### Bootstrapping users
To bootstrap the Encryptonize service with a user, once the service has been started, execute 
`./encryption-service create-user <scopes>`.  Here, `<scopes>` is a string describing the
scopes the users should have. Each scope is mapped to a character as described in the table below. 
The scopes are described in further detail in the [api doc](../api/api-v3.1.0.md). E.g., to create 
a user with `READ` and `CREATE` scopes, call `./encryption-service create-user rc`.

| Scope               | Character |
| ---                 | ---       |
| `READ`              | `r`       |
| `CREATE`            | `c`       |
| `UPDATE`            | `u`       |
| `DELETE`            | `d`       |
| `INDEX`             | `i`       |
| `OBJECTPERMISSIONS` | `o`       |
| `USERMANAGEMENT`    | `m`       |

Note that users created this way are only valid for other Encryption Services that use the same key material.
Information on bootstrapping in Docker and Kubernetes environments is provided in the following sections.

#### Docker example
If using docker run:
```
docker exec <CONTAINER ID> ./encryption-service create-user <scopes>
```

#### Kubernetes example
If using kubernetes with kubectl run:
```
kubectl -n encryptonize exec deployment/encryptonize -- /encryption-service create-user <scopes>
```
For more info on user management in Kubernetes, see the (Encryptonize Kubernetes README)[../../kubernetes/README].

### Generating users through API
To create a user through the API, you need to call the `authn.Encryptonize.CreateUser` endpoint. 
The request should contain an attribute named `userScopes` which enumerates all the scopes of the user
as described in the [API doc](../api/api-v3.1.0.md). 

Once a user has been created, a new `userID` and `password` will be returned from the call. 
Note that it is not possible to modify the scopes of a user after creation.

### User login
When a user is created, you get the User ID and the password. You can use this information to obtain the short-lived
access token, which is necessary for authentication towards the API. You can login by calling the 
`authn.Encryptonize.LoginUser` endpoint. Provide the User ID and the password in your request object.

Users can only be created by a user with the `USERMANAGEMENT` scope. For code examples on how to do this see
[`/applications/ECCS`](/applications/ECCS).

### Remove user
To remove a user, you need to call the `authn.Encryptonize.RemoveUser` endpoint. This endpoint requires the 
`USERMANAGEMENT` scope. The request must contain the `userId` of the user to be removed. If the request 
was succesful, you will receive an empty response.

# Storage
You can let Encryptonize store your encrypted data through the `storage.Encryptonize` API. In the following,
we provide a short description of the exposed endpoints.

## Storing data
To store data through the API, you need to call the `storage.Encryptonize.Store` endpoint. To access this 
endpoint the user must have the `CREATE` scope. The request should contain two attributes named `plaintext` 
and `associatedData`.

The `plaintext` is the data to be encrypted and stored. The `associatedData` is metadata attached
to the plaintext. The `associatedData` will not be encrypted, but it will be cryptographically
bound to the ciphertext, ensuring integrity and authenticity.
The `associatedData` can be used for indexing or other purposes.

The `objectId` will be returned from the operation. This value should be kept safe as it will be used to 
retrieve the object again from the service.

## Retrieving data
To retrieve data through the API, you need to call the `storage.Encryptonize.Retrieve` endpoint. 
To access this endpoint the user must have the `READ` scope. The operations takes the `objectId` of 
the object to be retrieved. If the operation is successful, the object is returned in decrypted 
format along with any associated data.

## Updating data
To update an existing object, you need to call the `storage.EncryptonizeUpdate` endpoint. To access this 
endpoint, the user must have the `UPDATE` scope. The request must contain the updated `plaintext`, 
the updated `associatedData` and the `objectId` of the object that needs to be updated. On a succesful 
request, the response will be empty. Note that concurrent updates/deletes of the same objects might lead to 
race conditions and is not safe.

## Deleting data
To delete an existing object, you need to call the `storage.Encryptonize.Delete` endpoint. To access 
this endopoint, the user must have the `DELETE` scope. The request must contain the `objectId` of 
the object which should be deleted. Note that concurrent updates/deletes of the same objects might lead to 
race conditions and is not safe.


# Storage-less encryption
The Encryptonize API allows to bypass the storage and instead return the encrypted packages back to the user.
This might be useful if you wish to manage the encrypted data yourself.

## Encryption
You can encrypt an object and get the encrypted package back using the `enc.Encryptonize.Encrypt endpoint`.
The callees need the `CREATE` scope in order to use this endpoint. Similar to the `Store` endpoint, you 
need to provide the `plaintext` and the `associatedData`. The response of this call will contain the 
`ciphertext`, the `associatedData` and the `objectId`. Note that the `associatedData` is not encrypted.

## Decryption
To decrypt an object, you need to call the `enc.Encryptonize.Decrypt` endpoint and provide the `ciphertext`,
`associatedData` and the `objectId` in the request. This endpoint requires the `READ` scope. 
If you are authenticated towards the API and authorized to read the object, the response will contain 
the `plaintext` and the `associatedData`.

# Permissions
Access to an object is shared through the concept of object permissions.

Every object has a list associated with it with the user IDs of the users who are able to access and 
modify the object. In order to modify the permission list, the user must have access to the object 
(i.e. be on the permission list of the object).

## Get permissions of an object
To get the permission list of an object, you need to call the `authz.Encryptonize.GetPermissions` endpoint. 
To access this endpoint the `INDEX` scope is required. The operation will return a list of `userID`s 
that have access to the object.

## Add permissions to an object
To add a user to the permission list of an object, you need to call the `authz.Encryptonize.AddPermission` 
endpoint. To access this endpoint the `OBJECTPERMISSIONS` scope is required.

## Remove permissions from an object
To remove a user's permission from an object, you need to call the `authz.Encryptonize.RemovePermission` endpoint. 
To access this endpoint the `OBJECTPERMISSIONS` scope is required.

# Version
To get version information about the running encryption service, you need to call the `app.Encryptonize.Version` 
endpoint. Currently, the endpoint returns the git commit hash and an optional git tag. This endpoint 
does not need any scopes but requires the user to be authenticated by presenting a valid access token. 
