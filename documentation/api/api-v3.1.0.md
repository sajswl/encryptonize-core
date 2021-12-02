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
This document introduces version 3.1.0 of the API for the Encryptionize&reg; Service.

The Encryptonize&reg; API exposes several service addresses: `app.Encryptonize`,
`storage.Encryptonize`, `enc.Encryptonize`, `authz.Encryptonize`, `authn.Encryptonize`, which define the following functions

### `app.Encryptonize`:
* `rpc Version (VersionRequest) returns (VersionResponse)`

### `storage.Encryptonize`:
* `rpc Store (StoreRequest) returns (StoreResponse)`
* `rpc Retrieve (RetriveRequest) returns (RetriveResponse)`
* `rpc Update (UpdateRequest) returns (UpdateResponse)`
* `rpc Delete (DeleteRequest) returns (DeleteResponse)`

### `enc.Encryptonize`:
* `rpc Encrypt (EncryptRequest) returns (EncryptResponse)`
* `rpc Decrypt (DecryptRequest) returns (DecryptResponse)`

### `authn.Encryptonize`:
* `rpc CreateUser (CreateUserRequest) returns (CreateUserResponse)`
* `rpc LoginUser (LoginUserRequest) returns (LoginUserResponse)`
* `rpc RemoveUser (RemoveUserRequest) returns (RemoveUserResponse)`
* `rpc CreateGroup (CreateGroupRequest) returns (CreateGroupResponse)`
* `rpc AddUserToGroup (AddUserToGroupRequest) returns (AddUserToGroupResponse)`
* `rpc RemoveUserFromGroup (RemoveUserFromGroupRequest) returns (RemoveUserFromGroupResponse)`

### `authz.Encryptonize`:
* `rpc GetPermissions (GetPermissionsRequest) returns (GetPermissionsResponse)`
* `rpc AddPermission (AddPermissionRequest) returns (AddPermissionResponse)`
* `rpc RemovePermission (RemovePermissionRequest) returns (RemovePermissionResponse)`

For detailed information, see below.

# Authorization

To authenticate a user needs to provide an access token via `authorization`. It should be in the form
`bearer <user access token>`. A correct authentication metadata query could look like this:
```
{
  "authorization": "bearer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
}
```

In order to obtain a token, see the `authn.CreateUser` and `authn.LoginUser` functions.

The access token consists of two parts separated by a dot (`.`). Each part is individually base64url
encoded. The first part is a wrapped encryption key. The second part is a serialized protobuf
message containing the user ID, a set of scopes, and an expiry time. This part is encrypted using
the wrapped key. The user ID is a UUID (version 4).

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

| Name                        | Scope             |
|-----------------------------|-------------------|
| `app.Version`               |                   |
| `storage.Store`             | CREATE            |
| `storage.Retrieve`          | READ              |
| `storage.Update`            | UPDATE            |
| `storage.Delete`            | DELETE            |
| `enc.Encrypt`               | CREATE            |
| `enc.Decrypt`               | READ              |
| `authn.CreateUser`          | USERMANAGEMENT    |
| `authn.LoginUser`           |                   |
| `authn.RemoveUser`          | USERMANAGEMENT    |
| `authn.CreateGroup`         | USERMANAGEMENT    |
| `authn.AddUserToGroup`      | USERMANAGEMENT    |
| `authn.RemoveUserFromGroup` | USERMANAGEMENT    |
| `authz.GetPermissions`      | INDEX             |
| `authz.AddPermission`       | OBJECTPERMISSIONS |
| `authz.RemovePermission`    | OBJECTPERMISSIONS |


* An unauthenticated request to the API returns: `Unauthenticated 16`.
* An unauthorized request to the API returns: `PermissionDenied 7`.

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

# Messages
The Encryptonize API defines several gRPC message types, mainly in the form of structs representing
requests and corresponding responses.

## `app`

### `app.VersionRequest`
The structure used as an argument for an `app.Version` request. The structure is empty.

### `app.VersionResponse`
The structure returned by an `app.Version` request. It contains the version information of the
currently running encryptonize deployment.

| Name        | Type   | Description                           |
|-------------|--------|---------------------------------------|
| `commit`    | string | Git commit hash                       |
| `tag`       | string | Git commit tag (if any)               |

## `storage`

### `storage.StoreRequest`
The structure used as an argument for a `storage.Store` request. It consists of the plaintext
(`plaintext`) and the associated data (`associated_data`). Requires the scope `CREATE`.

| Name              | Type   | Description                           |
|-------------------|--------|---------------------------------------|
| `plaintext`       | bytes  | The data to be encrypted              |
| `associated_data` | bytes  | The associated data for the plaintext |

### `storage.StoreResponse`
The structure returned by a `storage.Store` request. It contains the Object ID of the stored object.
The Object ID is important as it must be used to subsequently request the object in a
`storage.RetrieveRequest`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

### `storage.RetrieveRequest`
The structure used as an argument for a `storage.Retrieve` request. It contains the Object ID of the
Object the client wishes to retrieve. Requires the scope `READ`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

### `storage.RetrieveResponse`
The structure returned by a `storage.Retrieve` request. It consists of the plaintext (`plaintext`)
and the associated data (`associated_data`) matching the ID passed in the request.

| Name              | Type   | Description                           |
|-------------------|--------|---------------------------------------|
| `plaintext`       | bytes  | The data that was encrypted           |
| `associated_data` | bytes  | The associated data for the plaintext |

### `storage.UpdateRequest`
The structure used as an argument for a `storage.Update` request. It consists of the plaintext
(`plaintext`), the associated data (`associated_data`), and the Object ID of the object the client
wishes to update. Requires the scope `UPDATE`.

| Name              | Type   | Description                           |
|-------------------|--------|---------------------------------------|
| `plaintext`       | bytes  | The data to be encrypted              |
| `associated_data` | bytes  | The associated data for the plaintext |
| `object_id`       | string | The object identifier                 |

### `storage.UpdateResponse`
The structure returned by a `storage.Update` request. The structure is empty.

### `storage.DeleteRequest`
The structure used as an argument for a `storage.Delete` request. It containers the Object ID of the
Object the client wishes to delete. Requires the scope `DELETE`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

### `storage.DeleteResponse`
The structure returned by a `storage.Delete` request. The structure is empty.

## `enc`

### `enc.EncryptRequest`
The structure used as an argument for a `enc.Encrypt` request. 
It consists of the plaintext (`plaintext`) and the associated data (`associated_data`). 
Requires the scope `CREATE`.

| Name              | Type   | Description                           |
|-------------------|--------|---------------------------------------|
| `plaintext`       | bytes  | The data to be encrypted              |
| `associated_data` | bytes  | The associated data for the plaintext |

### `enc.EncryptResponse`
The structure returned by a `enc.Encrypt` request. It contains the Object ID of the stored object,
the ciphertext of the provided plaintext, and the associated data.
All of the parameters are important as they must be used to subsequently request the object in a
`enc.DecryptRequest`.

| Name               | Type   | Description                           |
|--------------------|--------|---------------------------------------|
| `ciphertext`       | bytes  | Ciphertext of the provided plaintext  |
| `associated_data`  | bytes  | The associated data for the plaintext |
| `object_id`        | string | The object identifier                 |

### `enc.DecryptRequest`

The structure used as an argument for a `enc.Decrypt` request, it is identical to `enc.EncryptResponse`.
It consists of the previously received ciphertext, Object ID and the provided associated data.
Requires the scope `READ`.

| Name               | Type   | Description                           |
|--------------------|--------|---------------------------------------|
| `ciphertext`       | bytes  | The data to be decrypted              |
| `associated_data`  | bytes  | The associated data for the ciphertext|
| `object_id`        | string | The object identifier                 |

### `enc.DecryptResponse`

The structure returned by a `enc.Decrypt` request. It consists of the plaintext of the provided cipheretext, 
and the provided associated data.

| Name              | Type   | Description                           |
|-------------------|--------|---------------------------------------|
| `plaintext`       | bytes  | The data that was decrypted           |
| `associated_data` | bytes  | The associated data for the plaintext |

## `authn`

### `authn.CreateUserRequest`
The structure used as an argument for a `authn.CreateUser` request. It contains a list of scopes
defining which endpoints the user has access to. Possible scopes are `READ`, `CREATE`, `INDEX`,
`OBJECTPERMISSIONS`, and `USERMANAGEMENT`. Requires the scope `USERMANAGEMENT`.

| Name     | Type         | Description                                      |
|----------|--------------|--------------------------------------------------|
| `scopes` | []enum Scope | An array of scopes the newly created user posses |

### `authn.CreateUserResponse`
The structure returned by a `authn.CreateUser` request. It contains the User ID and Password of
the newly created user.

| Name       | Type   | Description            |
|------------|--------|------------------------|
| `user_id`  | string | The generated user id  |
| `password` | string | The generated password |

### `authn.LoginUserRequest`
The structure used as an argument for a `authn.LoginUser` request. It contains the User ID
and Password of a previously created user.

| Name       | Type   | Description            |
|------------|--------|------------------------|
| `user_id`  | string | The generated user id  |
| `password` | string | The generated password |

### `authn.LoginUserResponse`
The structure returned by a `authn.LoginUser` request. It contains the User Access Token.
Note that the User Access Token is valid for 1 hour.

| Name           | Type   | Description                |
|----------------|--------|----------------------------|
| `access_token` | string | The generated access token |

### `authn.RemoveUserRequest`
The structure used as an argument for a `authn.RemoveUser` request. It contains the User ID
of the user that will be removed. Requires the scope `USERMANAGEMENT`.

| Name       | Type   | Description        |
|------------|--------|--------------------|
| `user_id`  | string | The target user id |

### `authn.RemoveUserResponse`
The structure returned by a `authn.RemoveUser` request. The structure is empty.

### `authn.CreateGroupRequest`
The structure used as an argument for a `authn.CreateGroup` request. It contains a list of scopes
defining which endpoints the group has access to. Possible scopes are `READ`, `CREATE`, `INDEX`,
`OBJECTPERMISSIONS`, and `USERMANAGEMENT`. Requires the scope `USERMANAGEMENT`.

| Name     | Type         | Description                                       |
|----------|--------------|---------------------------------------------------|
| `scopes` | []enum Scope | An array of scopes the newly created group posses |

### `authn.CreateGroupResponse`
The structure returned by a `authn.CreateGroup` request. It contains the Group ID of the newly
created group.

| Name       | Type   | Description            |
|------------|--------|------------------------|
| `group_id` | string | The generated group id |

### `authn.AddUserToGroupRequest`
The structure used as an argument for a `authn.AddUserToGroup` request. It contains a User ID and a group ID. The specified user will be added to the specified group. Requires the scope `USERMANAGEMENT`.

| Name       | Type   | Description         |
|------------|--------|---------------------|
| `user_id`  | string | The target user id  |
| `group_id` | string | The target group id |

### `authn.AddUserToGroupResponse`
The structure returned by a `authn.AddUserToGroup` request. The structure is empty.

### `authn.RemoveUserFromGroupRequest`
The structure used as an argument for a `authn.RemoveUserFromGroup` request. It contains a User ID and a group ID. The specified user will be removed from the specified group. Requires the scope `USERMANAGEMENT`.

| Name       | Type   | Description         |
|------------|--------|---------------------|
| `user_id`  | string | The target user id  |
| `group_id` | string | The target group id |

### `authn.RemoveUserFromGroupResponse`
The structure returned by a `authn.RemoveUserFromGroup` request. The structure is empty.

## `authz`

### `authz.GetPermissionsRequest`
The structure used as an argument for a `authz.GetPermissions` request. It contains the ID of the
Object the client wishes to get the permission list for. Requires the scope `OBJECTPERMISSIONS`.

| Name        | Type   | Description           |
|-------------|--------|-----------------------|
| `object_id` | string | The object identifier |

### `authz.GetPermissionsResponse`
The structure returned by a `storage.GetPermissions` request. It contains a list of group IDs of
groups with access to the Object specified in the request.

| Name        | Type     | Description           |
|-------------|----------|-----------------------|
| `group_ids` | []string | An array of group IDs |

### `authz.AddPermissionRequest`
The structure used as an argument for an `authz.AddPermission` request. It contains the ID of an
Object and a target group ID. The specified group ID will be added to the access list of the
specified object. Requires the scope `OBJECTPERMISSIONS`.

| Name        | Type   | Description                       |
|-------------|--------|-----------------------------------|
| `object_id` | string | The object                        |
| `target`    | string | The target for permission change  |

### `authz.AddPermissionResponse`
The structure returned by a `authz.AddPermission` request. The structure is empty.

### `authz.RemovePermissionRequest`
The structure used as an argument for a `authz.RemovePermission` request. It contains the ID of an
Object and a target group ID. The specified group ID will be removed from the access list of the
specified object. Requires the scope `OBJECTPERMISSIONS`.

| Name        | Type   | Description                           |
|-------------|--------|---------------------------------------|
| `object_id` | string | The object                            |
| `target`    | string | The target UID for permission change  |

### `authz.RemovePermissionResponse`
The structure returned by a `authz.RemovePermission` request. The structure is empty.

# Functions

## `app`

### `app.Version`

Gets the commit hash and tag (if exists) of the currently running service.

```
rpc Version (VersionRequest) returns (VersionResponse)
```

## `storage`

### `storage.Store`

Takes a `storage.StoreRequest` and Stores its contents in encrypted form. This call can fail if the
Storage Service cannot reach the object storage, in which case an error is returned.

```
rpc Store (StoreRequest) returns (StoreResponse)
```

### `storage.Retrieve`

Fetches a previously Stored object and returns the plaintext content. This call can fail if the
specified object does not exist, if the caller does not have access permission to that object, or if
the Storage Service cannot reach the object storage. In these cases, an error is returned.

```
rpc Retrieve (RetriveRequest) returns (RetriveResponse)
```

### `storage.Update`

Takes a `storage.UpdateRequest` and Stores it in encrypted form, replacing the data previously
stored with the given Object ID. This call can fail if the specified Object ID does not currently
exist, if the caller does not have access permission to that object, or if the Storage Service
cannot reach the object storage. In these cases, an error is returned.

> DISCLAIMER: Current implementation of `storage.Update` does not ensure safe concurrent access.

```
rpc Update (UpdateRequest) returns (UpdateResponse)
```

### `storage.Delete`

Deletes a previously Stored object. This call does not fail if the specified object does not exist.
It can fail if the caller does not have access permission to that object or if the Storage Service
cannot reach the object storage. In these cases, an error is returned.

> DISCLAIMER: Current implementation of `storage.Delete` does not ensure safe concurrent access.

```
rpc Delete (DeleteRequest) returns (DeleteResponse)
```

## `enc`

### `enc.Encrypt`

Takes an `enc.EncryptRequest` and encrypts its contents returning the ciphertext **without** storing it.

```
rpc Encrypt (EncryptRequest) returns (EncryptResponse) 
```

### `enc.Decrypt`

Takes a `enc.DecryptRequest`, authorizes the user for access permissions and if accessible, 
returns the decrypted content.

```
rpc Decrypt (DecryptRequest) returns (DecryptResponse)
```

## `authn`

### `authn.CreateUser`

Creates a new user. Also creates a group with the same ID as the user and the same scopes. The user
is added to this group. This call can fail if the caller is lacking the required scope or if the
Auth Service cannot reach the auth storage, in which case an error is returned.

```
rpc CreateUser (CreateUserRequest) returns (CreateUserResponse)
```

### `authn.LoginUser`

Logs in an existing user, returning a User Access Token. Note that this token is valid for 1 hour.
This call can fail if the caller provides the wrong credentials or if the Auth Service cannot reach
the auth storage, in which case an error is returned.

```
rpc LoginUser (LoginUserRequest) returns (LoginUserResponse)
```

### `authn.RemoveUser`

Deletes an existing user. This call can fail if the caller is lacking the required scope, if the
user does not exist, or if the Auth Service cannot reach the auth storage, in which case an error is
returned.

```
rpc RemoveUser (RemoveUserRequest) returns (RemoveUserResponse)
```

### `authnCreateGroup`
Creates a new group. This call can fail if the caller is lacking the required scope or if the Auth
Service cannot reach the auth storage, in which case an error is returned.

```
rpc CreateGroup (CreateGroupRequest) returns (CreateGroupResponse)
```

### `authnAddUserToGroup`
Adds a user to a group. This call can fail if the caller is lacking the required scope or if the
Auth Service cannot reach the auth storage, in which case an error is returned.

```
rpc AddUserToGroup (AddUserToGroupRequest) returns (AddUserToGroupResponse)
```

### `authnRemoveUserFromGroup`
Removes a user from a group. This call can fail if the caller is lacking the required scope or if
the Auth Service cannot reach the auth storage, in which case an error is returned.

```
rpc RemoveUserFromGroup (RemoveUserFromGroupRequest) returns (RemoveUserFromGroupResponse)
```

## `authz`

### `authz.GetPermissions`

Returns a list of groups with access to the specified object. This call can fail if the Storage
Service cannot reach the auth storage, in which case an error is returned. The calling user has to
be authenticated and authorized to access the object in order to get the object permissions.

```
rpc GetPermissions (GetPermissionsRequest) returns (GetPermissionsResponse)
```

### `authz.AddPermission`

Adds a group to the access list of the specified object. This call can fail if the caller does not
have access to the object, if the target group does not exist, or if the Storage Service cannot
reach the auth storage. In these cases, an error is returned.

```
rpc AddPermission (AddPermissionRequest) returns (ReturnCode)
```

### `authz.RemovePermission`

Removes a group from the access list of the specified object. This call can fail if the caller does
not have access to the object or if the Storage Service cannot reach the auth storage. In these
cases, an error is returned.

```
rpc RemovePermission (RemovePermissionRequest) returns (ReturnCode)
```
