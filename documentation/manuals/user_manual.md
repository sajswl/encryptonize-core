# License
Copyright 2020 CYBERCRYPT

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
This document will provide a quick introduction on how to use the Encryptonize service and introduce
essential concepts and terminology. For a detailed description of the gRPC API, see [the
specification](../api/api-v2.md).

1. [Authentication](#authentication)
1. [Users](#users)
    1. [Managing Users](#managing-users)
        1. [Bootstrapping admin user](#bootstrapping-admin-user)
        1. [Generating users through API](#generating-users-through-api)
1. [Storage](#storage)
    1. [Storing data](#storing-data)
    1. [Retrieving data](#retrieving-data)
1. [Permissions](#permissions)
    1. [Get permissions of an object](#get-permissions-of-an-object)
    1. [Add permissions to an object](#add-permissions-to-an-object)
    1. [Remove permissions from an object](#get-version-information)
1. [Version](#version)
1. [Troubleshooting](#troubleshooting)
    1. [Common Errors](#common-errors)

# Terminology
Terminology specific to the Encryptonize service is introduced when needed. Every term will be
marked in **bold**. Value types are called by their protobuf name. For an overview of these names
translated to supported languages see this
[list](https://developers.google.com/protocol-buffers/docs/proto3#scalar).

# Authentication
All authentication on the Encryptonize service is done via gRPC metadata. The metadata should
consist of the pairs: `authorization` and `userID`. The `authorization` should contain the user
access token and be in the form `bearer <user access token>`. The `userID` should contain the
user identifier. A correct authentication metadata query could look like this:
```
{
  "authorization": "bearer 0000000000000000000000000000000000000000000000000000000000000000",
  "userID": "00000000-0000-4000-0000-000000000002",
}
```
The user ID is a unique identifier (UUID v4). The access token is a 256 bit value represented as a hex string.

Currently the Encryptonize service supports two kinds of tokens:

* Admin token: Grants permission to manage users for the service.
* User token: Grants permission to store and retrieve data. It also grants permissions to view, add,
  and remove object permissions.

# Users
A **user** is an authorization entity on the encryption server, and is only represented by a user ID.
The user ID is used to identify a single user. Each user has an access token which is used, along
with the user ID, for authentication and authorization. A user can share stored data with other users
by modifying the permissions on an object. Instructions on how to share data
between users can be found in the section on [*Permissions*](#permissions). The user that creates
an object automatically has permission to acccess that object, and any user that can access an object
can modify the permissions.

It should be noted that while the access token should be kept secret, user IDs can be considered
public information and safely shared between parties.

All IDs are of the format version 4 UUID ([RFC 4122](https://tools.ietf.org/html/rfc4122) section 4.4)  and access tokens are 64 character hex strings.

## Managing Users
### Bootstraping admin user
To bootstrap the Encryptonize service with an admin user, once the service has been started, connect
to it and execute `./es-service create-admin`. Note that admin users created this way are only valid
for other Encryption Services that use the same key material.

#### Docker example
If using docker run:
```
docker exec <CONTAINER ID> ./es create-admin
```

#### Kubernetes example
If using kubernetes with kubectl run:
```
kubectl exec <encryptonize pod name> -n encryptonize -- /es create-admin
```
It doesn't matter which pod is used, as long as it's running the Encryptionize service.
You can get a list of pods running Encryptonize by running:
```
kubectl get pods -n encryptonize
```

### Generating users through API
To create a user through the API, you need to call the `CreateUser` endpoint. The `CreateUser`
endpoint requires a payload of type `CreateUserRequest`. This payload consists of a single attribute
named `userKind` of type `enum UserKind` and determines which kind of user is created. Accptable
values for `userKind` are either `ADMIN` or `USER`.
Once a user has been created, a new `userID` and `accessToken` will be returned from the call.

Users can only be created by an admin user. For code examples on how to do this see
[`/applications/ECCS`](/applications/ECCS).

# Storage
To distinguish between encrypted and unencrypted data, some terminology is necessary. An **object**
is defined as the plaintext payload sent to the Encryptonize service. A **package** will be
defined as the encrypted plaintext and associated data.

Note that admin users cannot directly store or retrieve objects from the storage.

## Storing data
To store data through the API, you need to call the `Store` endpoint. The request should contain two attributes named `plaintext` and `associatedData`.

The `plaintext` is the data to be encrypted and stored. The `associatedData` is metadata supplied
to the plaintext. The `associatedData` will not be encrypted, but it will be cryptographically
bound to the ciphertext, ensuring integrity and authenticity.
The  `associatedData` can be used for indexing or other purposes.

The `objectId` will be returned from the operation. This value should be kept safe as it will be used to retrieve the object again from the service.

## Retrieving data
To retrieve data through the API, you need to call the `Retrieve` endpoint. The operations takes
the `objectId` of the object to be retrieved.
If the operation is successful, the object is returned in decrypted format along with any associated data.

# Permissions
Access to an object is shared through the concept of object permissions.

Every object has a list associated with it with the user IDs of the
users who are able to access and modify the object.
In oder to modify the permission list, the user must have access to the object (i.e. be on the permission list of the object).

## Get permissions of an object
To get the permission list of an object, you need to call the `GetPermissions` endpoint. The operation will return a list of `userID`s that have access to the object.

## Add permissions to an object
To add a user to the permission list of an object, you need to call the `AddPermission` endpoint.

## Remove permissions from an object
To remove a user's permission from an object, you need to call the `RemovePermission` endpoint.

# Version
To get version information about the running encryption service, you need to call the `Version` endpoint. Currently, the endpoint returns the git commit hash and an optional git tag.