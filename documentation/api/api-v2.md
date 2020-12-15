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
This document introduces version 2.0 of the API for the Encryptionize Service.

A primary change from 1.0 of the Encryptonize API is to introduce gRPC instead of REST for the API.

The current service address is `app.Encryptonize`. The Encryptonize API defines the following functions:

* `rpc Store (StoreRequest) returns (StoreResponse)`
* `rpc Retrieve (RetriveRequest) returns (RetriveResponse)`
* `rpc GetPermission (GetPermissionRequest) returns (GetPermissionResponse)`
* `rpc AddPermission (AddPermissionRequest) returns (ReturnCode)`
* `rpc RemovePermission (RemovePermissionRequest) returns (ReturnCode)`
* `rpc CreateUser (CreateUserRequest) returns (CreateUserResponse)`
* `rpc Version (VersionRequest) returns (VersionResponse)`

For detailed information, see below.

# Error Handling
The Encryption Service uses [grpc/codes](https://godoc.org/google.golang.org/grpc/codes) and
[grpc/status](https://godoc.org/google.golang.org/grpc/status) for error messages. The main error
codes returned by the service is:
* *InvalidArgument (3)*: The user supplied an argument that was invalid.
* *Unauthenticated (16)*: The user was not authenticated.
* *PermissionDenied (7)*: The user was not authorized.
* *Internal (13)*: An internal error occurred. Most likely one of the storage servers is in an
  unhealthy state.

# Health checks
To check if the service is running and serving use the `grpc_health_probe` tool. Documentation on this tool can be found [here](https://github.com/grpc-ecosystem/grpc-health-probe/). Documentation on interaction with the health checks in a Kubernetes context can be found [here](https://kubernetes.io/blog/2018/10/01/health-checking-grpc-servers-on-kubernetes/).

# Primitive Types
The Encryptonize API currently only defines one primitive type, namely the `Object`.

## Object
The `Object` struct represents data stored and retrieved by a client, and consists of the plaintext
(`plaintext`) and the associatedData (`associatedData`).

| Name            | Type   | Description                           |
|-----------------|--------|---------------------------------------|
| plaintext       | bytes  | The data to be encrypted              |
| associated_data | bytes  | The associated data for the plaintext |

# Derived types
The Encryptonize API defines several derived types, mainly in the form of structs representing
requests and corresponding responses.

## StoreRequest
The structure used as an argument for a `Store` request. It contains a single `Object`.

| Name   | Type   | Description |
|--------|--------|-------------|
| Object | Object | The object  |

## StoreResponse
The structure returned by a `Store` request. It contains the Object ID of the stored `Object`. The Object ID is important as it can be used to subsequent request the object in a `RetrieveRequest`.

| Name      | Type   | Description           |
|-----------|--------|-----------------------|
| object_id | string | The object identifier |

## RetrieveRequest
The structure used as an argument for a `Retrieve` request. It contains the Object ID of the Object
the client wishes to retrieve.

| Name      | Type   | Description           |
|-----------|--------|-----------------------|
| object_id | string | The object identifier |

## RetrieveResponse
The structure returned by a `Retrieve` request. It contains the `Object` matching the ID passed in
the request.

| Name             | Type             | Description           |
|------------------|------------------|-----------------------|
| object           | Object           | The object            |

## CreateUserRequest
The structure used as an argument for a `CreateUser` request. It contains a string defining which
time of user to create. The two types of users are `admin` and `user`.

| Name      | Type          | Description                    |
|-----------|---------------|--------------------------------|
| user_kind | enum UserKind | The type of user to be created |

## CreateUserResponse
The structure returned by a `CreateUser` request. It contains the User ID and User Access Token of
the newly created user.

| Name        | Type   | Description                |
|-------------|--------|----------------------------|
| userID      | string | The generated user id      |
| accessToken | string | The generated access token |

## GetPermissionRequest
The structure used as an argument for a `GetPermission` request. It contains the ID of the Object
the client wishes to get the permission list for.

| Name      | Type   | Description           |
|-----------|--------|-----------------------|
| object_id | string | The object identifier |

## GetPermissionResponse
The structure returned by a `GetPermissions` request. It contains a list of User IDs of users with
access to the Object specified in the request.

| Name     | Type     | Description         |
|----------|----------|---------------------|
| user_ids | []string | An array of userIDs |

## AddPermissionRequest
The structure used as an argument for an `AddPermission` request. It contains the ID of the Object
the client wishes to add permissions to and the User ID of the user to be added to the access list.

| Name      | Type   | Description                       |
|-----------|--------|-----------------------------------|
| object_id | string | The object                        |
| target    | string | The target for permission change  |

## RemovePermissionRequest
The structure used as an argument for a `RemovePermission` request. It contains the ID of the Object
the client wishes to remove permissions from and the User ID of the user to be removed from the
access list.

| Name      | Type   | Description                           |
|-----------|--------|---------------------------------------|
| object_id | string | The object                            |
| target    | string | The target UID for permission change  |

## VersionResponse
The structure returned by a `Version` request. It contains the version information of the currently
running encryptonize deployment.

| Name      | Type   | Description                           |
|-----------|--------|---------------------------------------|
| commit    | string | Git commit hash                       |
| tag       | string | Git commit tag (if any)               |

# Authorization

To authenticate a user should provide some metadata to the gRPC. The Metadata should consist of the
pairs: `authorization` and `userID`. The `authorization` should contain the user access token and be
in the form `bearer <user access token>`. The `userID` should simply contain the user identifier. A
correct authentication metadata query could look like this:
```
{
  "authorization": "bearer 0000000000000000000000000000000000000000000000000000000000000000",
  "userID": "00000000-0000-4000-0000-000000000002",
}
```
The user ID is a UUID (version 4). The access token is a cryptographically randomly generated 256
bit value represented as a hex string.

An unauthenticated request to the API returns: `Unauthenticated 16`

An unauthorized request to the API returns: `PermissionDenied 7`

# Store

Takes an `Object` and Stores it in encrypted form. This call can fail if the Encryption Service
cannot reach the object storage, in which case an error is returned.

```
rpc Store (StoreRequest) returns (StoreResponse)
```

# Retrieve

Fetches a previously Stored `Object` and returns the plaintext content. This call can fail if the
specified object does not exist, if the caller does not have access permission to that object, or if
the Encryption Service cannot reach the object storage. In these cases, an error is returned.

```
rpc Retrieve (RetriveRequest) returns (RetriveResponse)
```

# Get Permission

Returns a list of users with access to the sepcified `Object`. This call can fail if the Encryption
Service cannot reach the auth storage, in which case an error is returned.

```
rpc GetPermission (GetPermissionRequest) returns (GetPermissionResponse)
```

# Add Permission

Adds a User to the access list of the specified `Object`. This call can fail if the caller does not
have access to the `Object`, if the target user does not exist, or if the Encryption Service cannot reach the auth storage. In these
cases, an error is returned.

```
rpc AddPermission (AddPermissionRequest) returns (ReturnCode)
```

# Remove Permission

Removes a User from the access list of the specified `Object`. This call can fail if the caller does
not have access to the `Object` or if the Encryption Service cannot reach the auth storage. In these
cases, an error is returned.

```
rpc RemovePermission (RemovePermissionRequest) returns (ReturnCode)
```

# Create a new user

Creates a new user. This call can fail if the caller is not an admin or of the Encryption Service
cannot reach the auth storage, in which case an error is returned.

```
rpc CreateUser (CreateUserRequest) returns (CreateUserResponse)
```

# Get version of the running service

Gets the commit hash and tag (if exists) of the currently running service.

```
rpc Version (VersionRequest) returns (VersionResponse)
```
