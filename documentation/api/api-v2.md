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
This document introduces version 2.0 of the API for the Encryptionize&reg; Service.

A primary change from 1.0 of the Encryptonize&reg; API is to introduce gRPC instead of REST for the
API.

The Encryptonize&reg; API exposes several service addresses: `app.Encryptonize`,
`storage.Encryptonize`, `authn.Encryptonize`, which define the following functions

### `app.Encryptonize`:
* `rpc Version (VersionRequest) returns (VersionResponse)`

### `storage.Encryptonize`:
* `rpc Store (StoreRequest) returns (StoreResponse)`
* `rpc Retrieve (RetriveRequest) returns (RetriveResponse)`
* `rpc Update (UpdateRequest) returns (UpdateResponse)`
* `rpc Delete (DeleteRequest) returns (DeleteResponse)`
* `rpc GetPermissions (GetPermissionsRequest) returns (GetPermissionsResponse)`
* `rpc AddPermission (AddPermissionRequest) returns (AddPermissionResponse)`
* `rpc RemovePermission (RemovePermissionRequest) returns (RemovePermissionResponse)`
* `rpc GetPermission (GetPermissionRequest) returns (GetPermissionResponse)`
* `rpc AddPermission (AddPermissionRequest) returns (ReturnCode)`
* `rpc RemovePermission (RemovePermissionRequest) returns (ReturnCode)`

### `authn.Encryptonize`:
* `rpc CreateUser (CreateUserRequest) returns (CreateUserResponse)`
* `rpc LoginUser (LoginUserRequest) returns (LoginUserResponse)`
* `rpc RemoveUser (RemoveUserRequest) returns (RemoveUserResponse)`

For detailed information, see below.

# Authorization

To authenticate a user needs to provide an access token via `authorization`. It should be in the form
`bearer <user access token>`. A correct authentication metadata query could look like this:
```
{
  "authorization": "bearer ChAAAAAAAABAAIAAAAAAAAAC.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
}
```

In order to obtain a token, see the `authn.CreateUser` and `authn.LoginUser` functions.

The access token consists of three parts separated by a dot. Each part is individually base64url
encoded. The first part is a serialized protobuf message containing the user ID and set of scopes.
The second part is a nonce to make the token unique even if the user ID and set of scopes is
identical to another token. The third part is an HMAC for integrity protection. The HMAC is created
as `HMAC(nonce||message)`.

This user ID is a UUID (version 4).

A user is created with a chosen set of scopes that governs the endpoints this user may access.
Any combination of the different scopes is valid. The scopes are:
- `READ`
- `CREATE`
- `INDEX`
- `OBJECTPERMISSIONS`
- `USERMANAGEMENT`
- `UPDATE`
- `DELETE`

To access the endpoints the following permissions are necessary:

| Name                       | Scope             |
|----------------------------|-------------------|
| `app.Version`              |                   |
| `storage.Store`            | CREATE            |
| `storage.Retrieve`         | READ              |
| `storage.Update`           | UPDATE            |
| `storage.Delete`           | DELETE            |
| `storage.GetPermission`    | INDEC             |
| `storage.AddPermission`    | OBJECTPERMISSIONS |
| `storage.RemovePermission` | OBJECTPERMISSIONS |
| `authn.CreateUser`         | USERMANAGEMENT    |
| `authn.LoginUser`          |                   |
| `authn.RemoveUser`         | USERMANAGEMENT    |


An unauthenticated request to the API returns: `Unauthenticated 16`

An unauthorized request to the API returns: `PermissionDenied 7`

# Error Handling
The Encryptonize&reg; API uses [grpc/codes](https://godoc.org/google.golang.org/grpc/codes) and
[grpc/status](https://godoc.org/google.golang.org/grpc/status) for error messages. The main error
codes returned by the service is:
* *InvalidArgument (3)*: The user supplied an argument that was invalid.
* *Unauthenticated (16)*: The user was not authenticated.
* *PermissionDenied (7)*: The user was not authorized.
* *Internal (13)*: An internal error occurred. Most likely one of the storage servers is in an
  unhealthy state.

# Health checks
To check if the service is running and serving use the `grpc_health_probe` tool. Documentation on
this tool can be found [here](https://github.com/grpc-ecosystem/grpc-health-probe/). Documentation
on interaction with the health checks in a Kubernetes context can be found
[here](https://kubernetes.io/blog/2018/10/01/health-checking-grpc-servers-on-kubernetes/).

# Primitive Types
The Encryptonize API currently only defines one primitive type, namely the `storage.Object`.

## `storage.Object`
The `storage.Object` struct represents data stored and retrieved by a client, and consists of the
plaintext (`plaintext`) and the associated data (`associated_data`).

| Name              | Type   | Description                           |
|-------------------|--------|---------------------------------------|
| `plaintext`       | bytes  | The data to be encrypted              |
| `associated_data` | bytes  | The associated data for the plaintext |

# Derived types
The Encryptonize API defines several derived types, mainly in the form of structs representing
requests and corresponding responses.

## `app.VersionRequest`
The structure used as an argument for an `app.Version` request. The structure is empty.

## `app.VersionResponse`
The structure returned by an `app.Version` request. It contains the version information of the
currently running encryptonize deployment.

| Name        | Type   | Description                           |
|-------------|--------|---------------------------------------|
| `commit`    | string | Git commit hash                       |
| `tag`       | string | Git commit tag (if any)               |

## `storage.StoreRequest`
The structure used as an argument for a `storage.Store` request. It contains a single
`storage.Object`. Requires the scope `CREATE`.

| Name     | Type   | Description |
|----------|--------|-------------|
| `object` | Object | The object  |

## `storage.StoreResponse`
The structure returned by a `storage.Store` request. It contains the Object ID of the stored
`storage.Object`. The Object ID is important as it can be used to subsequent request the object in a
`storage.RetrieveRequest`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

## `storage.RetrieveRequest`
The structure used as an argument for a `storage.Retrieve` request. It contains the Object ID of the
Object the client wishes to retrieve. Requires the scope `READ`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

## `storage.RetrieveResponse`
The structure returned by a `storage.Retrieve` request. It contains the `storage.Object` matching
the ID passed in the request.

| Name               | Type             | Description           |
|--------------------|------------------|-----------------------|
| `object`           | Object           | The object            |

## `storage.UpdateRequest`
The structure used as an argument for a `storage.Update` request. It contains a single
`storage.Object` and the Object ID of the Object the client wishes to update. Requires the scope
`UPDATE`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object`    | Object | The object            |
| `object_id` | string | The object identifier |

## `storage.UpdateResponse`
The structure returned by a `storage.Update` request. The structure is empty.

## `storage.DeleteRequest`
The structure used as an argument for a `storage.Delete` request. It containers the Object ID of the
Object the client wishes to delete. Requires the scope `DELETE`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

## `storage.DeleteResponse`
The structure returned by a `storage.Delete` request. The structure is empty.

## `storage.GetPermissionRequest`
The structure used as an argument for a `storage.GetPermission` request. It contains the ID of the
Object the client wishes to get the permission list for. Requires the scope `OBJECTPERMISSIONS`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

## `storage.GetPermissionResponse`
The structure returned by a `storage.GetPermissions` request. It contains a list of User IDs of
users with access to the Object specified in the request.

| Name       | Type     | Description         |
|------------|----------|---------------------|
| `user_ids` | []string | An array of userIDs |

## `storage.AddPermissionRequest`
The structure used as an argument for an `storage.AddPermission` request. It contains the ID of the
Object the client wishes to add permissions to and the User ID of the user to be added to the access
list. Requires the scope `OBJECTPERMISSIONS`.

| Name        | Type   | Description                       |
|-------------|--------|-----------------------------------|
| `object_id` | string | The object                        |
| `target`    | string | The target for permission change  |

## `storage.AddPermissionResponse`
The structure returned by a `storage.AddPermission` request. The structure is empty.

## `storage.RemovePermissionRequest`
The structure used as an argument for a `storage.RemovePermission` request. It contains the ID of
the Object the client wishes to remove permissions from and the User ID of the user to be removed
from the access list. Requires the scope `OBJECTPERMISSIONS`.

| Name        | Type   | Description                           |
|-------------|--------|---------------------------------------|
| `object_id` | string | The object                            |
| `target`    | string | The target UID for permission change  |

## `storage.RemovePermissionResponse`
The structure returned by a `storage.RemovePermission` request. The structure is empty.

## `authn.CreateUserRequest`
The structure used as an argument for a `authn.CreateUser` request. It contains a list of scopes
defining which endpoints the user has access to. Possible scopes are `READ`, `CREATE`, `INDEX`,
`OBJECTPERMISSIONS`, and `USERMANAGEMENT`. Requires the scope `USERMANAGEMENT`.

| Name          | Type             | Description                                      |
|---------------|------------------|--------------------------------------------------|
| `user_scopes` | []enum UserScope | An array of scopes the newly created user posses |

## `authn.CreateUserResponse`
The structure returned by a `authn.CreateUser` request. It contains the User ID and Password of
the newly created user.

| Name       | Type   | Description            |
|------------|--------|------------------------|
| `user_id`  | string | The generated user id  |
| `password` | string | The generated password |

## `authn.LoginUserRequest`
The structure used as an argument for a `authn.LoginUserRequest` request. It contains the User ID
and Password of a previously created user.

| Name       | Type   | Description            |
|------------|--------|------------------------|
| `user_id`  | string | The generated user id  |
| `password` | string | The generated password |

## `authn.LoginUserResponse`
The structure returned by a `authn.LoginUserResponse` request. It contains the User Access Token.

| Name           | Type   | Description                |
|----------------|--------|----------------------------|
| `access_token` | string | The generated access token |

## `authn.RemoveUserRequest`
The structure used as an argument for a `authn.RemoveUserRequest` request. It contains the User ID
of the user that will be removed. Requires the scope `USERMANAGEMENT`.

| Name       | Type   | Description        |
|------------|--------|--------------------|
| `user_id`  | string | The target user id |

## `authn.RemoveUserResponse`
The structure returned by a `authn.RemoveUser` request. The structure is empty.


# Functions

## `app.Version`

Gets the commit hash and tag (if exists) of the currently running service.

```
rpc Version (VersionRequest) returns (VersionResponse)
```

## `storage.Store`

Takes a `storage.Object` and Stores it in encrypted form. This call can fail if the Storage Service
cannot reach the object storage, in which case an error is returned.

```
rpc Store (StoreRequest) returns (StoreResponse)
```

## `storage.Retrieve`

Fetches a previously Stored `storage.Object` and returns the plaintext content. This call can fail
if the specified object does not exist, if the caller does not have access permission to that
object, or if the Storage Service cannot reach the object storage. In these cases, an error is
returned.

```
rpc Retrieve (RetriveRequest) returns (RetriveResponse)
```

## `storage.Update`

Takes a `storage.Object`  and an Object ID and Stores it in encrypted form, replacing the previous
`storage.Object` that was stored with that Object ID. This call can fail if the specified Object ID
does not currently exist, if the caller does not have access permission to that object, or if the
Storage Service cannot reach the object storage. In these cases, an error is returned.

> DISCLAIMER: Current implementation of `storage.Update` does not ensure safe concurrent access.

```
rpc Update (UpdateRequest) returns (UpdateResponse)
```

## `storage.Delete`

Deletes a previously Stored `storage.Object`. This call does not fail if the specified object does
not exist. It can fail if the caller does not have access permission to that object or if the
Storage Service cannot reach the object storage. In these cases, an error is returned.

> DISCLAIMER: Current implementation of `storage.Delete` does not ensure safe concurrent access.

```
rpc Delete (DeleteRequest) returns (DeleteResponse)
```

## `storage.GetPermissions`

Returns a list of users with access to the specified `storage.Object`. This call can fail if the
Storage Service cannot reach the auth storage, in which case an error is returned. The user has to
be authenticated and authorized in order to get the object permissions.

```
rpc GetPermission (GetPermissionRequest) returns (GetPermissionResponse)
```

## `storage.AddPermission`

Adds a User to the access list of the specified `storage.Object`. This call can fail if the caller
does not have access to the `storage.Object`, if the target user does not exist, or if the Storage
Service cannot reach the auth storage. In these cases, an error is returned.

```
rpc AddPermission (AddPermissionRequest) returns (ReturnCode)
```

## `storage.RemovePermission`

Removes a User from the access list of the specified `storage.Object`. This call can fail if the
caller does not have access to the `storage.Object` or if the Storage Service cannot reach the auth
storage. In these cases, an error is returned.

```
rpc RemovePermission (RemovePermissionRequest) returns (ReturnCode)
```

## `authn.CreateUser`

Creates a new user. This call can fail if the caller is lacking the required scope or if the Auth
Service cannot reach the auth storage, in which case an error is returned.

```
rpc CreateUser (CreateUserRequest) returns (CreateUserResponse)
```

## `authn.LoginUser`

Logs in an existing user, returning a User Access Token. This call can fail if the caller the wrong
credentials or if the Auth Service cannot reach the auth storage, in which case an error is
returned.

```
rpc LoginUser (LoginUserRequest) returns (LoginUserResponse)
```

## `authn.RemoveUser`

Deletes an existing user. This call can fail if the caller is lacking the required scope, if the
user does not exist, or if the Auth Service cannot reach the auth storage, in which case an error is
returned.

```
rpc RemoveUser (RemoveUserRequest) returns (RemoveUserResponse)
```
