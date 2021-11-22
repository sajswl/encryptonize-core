# Encryptonize Core Cloud Storage 3.1.0

Encryptonize Core Cloud Storage is an example of an easy to use CLI tool for storing secrets with the Encryptonize solution. It is ment as a starting point / code example for developers who want to interact with Encryptonize.

# Compilation
You will need to have `go` installed on your system. Instructions on installing go can be found [HERE](https://golang.org/doc/install)

You will need the `protobuf-compiler`. Instructions on how to install it can be found [HERE](https://grpc.io/docs/protoc-installation/).

You will also need the protobuf-compiler extention for golang. Instructions on how to install it can be found [HERE](https://grpc.io/docs/languages/go/quickstart/#prerequisites).

To compile the application, simply run
```
make build
```

# Usage

To use the ECCS sample application you need to add your user credentials and the Encryptonize endpoint as environmental variables.
Add your endpoint as `export ECCS_ENDPOINT=<endpoint>:9000`

If you setup the encryption server to use TLS you will also need to set `ECCS_CRT` depending on your needs:
`export ECCS_CRT=""` if the server uses a certiface derieved from a trusted root certificate
`export ECCS_CRT=$(cat encryption-server.crt)` if the encryption server uses a self signed certificate
`export ECCS_CRT=insecure` if you want to skip certificate validity checking

## Global Flags

The following flag applies to all commands:

`-a`, `--token` - user access token

## Store
The base command for storage is
```
./eccs -a <uat> store <flags>
```

### Flags

`-f`, `--filename` - path to the file to be stored

`-s`, `--stdin` - read directly from `STDIN`

`-d`, `--associateddata` - Associated data to be stored along with the object

### Examples
Store file:
```
./eccs -a <uat> store -f ./super_secret_document.pdf
```
Store file with associated data:
```
./eccs -a <uat> store -f ./super_secret_document.pdf -d "index1:someData1,index2:someMoreData"
```

Store from `STDIN`:
```
echo "In case of fire: git commit; git push" | ./eccs -a <uat> store -s
```

## Retrieve
The base command for retrieve is
```
./eccs -a <uat> retrieve <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to be retrieved

### Examples
Retrieve file:
```
./eccs -a <uat> retrieve -o 36ccd006-c063-4765-a909-ad398dbfd413
```

## Update
The base command for updating an object is
```
./eccs -a <uat> update <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to be updated

`-f`, `--filename` - path to the file containing updated data

`-s`, `--stdin` - read updated data directly from `STDIN`

`-d`, `--associateddata` - updated associated data

### Examples
Update from file:
```
./eccs -a <uat> update -o <oid> -f ./updated_document.pdf -d "index1:newIndex"
```
Update from `STDIN`:
```
echo "Some updated data." | ./eccs -a <uat> update -o <oid> -s -d "index1:newIndex"
```

## Delete
The base command for deleting an object is
```
./eccs -a <uat> delete <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to be deleted

### Examples
Delete object:
```
./eccs -a <uat> delete -o <oid>
```

## GetPermissions
The base command to get permissions for an object is
```
./eccs -a <uat> getpermissions <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to get permissions list from

### Examples
Get permissions list of a file:
```
./eccs -a <uat> getpermissions -o 36ccd006-c063-4765-a909-ad398dbfd413
```

## AddPermission
The base command to add a permission to an object is
```
./eccs -a <uat> addpermission <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to add a permission to
`-t`, `--target` - the uid of the user or the group to add to the permissions list

### Examples
Add a permission to a file:
```
./eccs -a <uat> addpermission -o 36ccd006-c063-4765-a909-ad398dbfd413 -t 31c7e8e5-15b8-42da-a4ce-9ac812cb0927
```

## RemovePermission
The base command to remove a permission from an object is
```
./eccs -a <uat> removepermission <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to remove a permission from
`-t`, `--target` - the uid of the user or the group to remove from the permissions list

### Examples
Remove a permission to a file:
```
./eccs -a <uat> removepermission -o 36ccd006-c063-4765-a909-ad398dbfd413 -t 31c7e8e5-15b8-42da-a4ce-9ac812cb0927
```

## CreateUser
The base command to create a user on the Encryptonize service is:
```
./eccs -a <uat> createuser <flags>
```
Keep in mind that to create a user, the credentials supplied via `ECCS_UID` and `ECCS_UAT` must
belong to a user with the `USERMANAGEMENT` scope.

### Flags

`-r`, `--read` - grants the Read scope
`-c`, `--create` - grants the Create scope
`-u`, `--update` - grants the Update scope
`-i`, `--index` - grants the Index scope
`-p`, `--object_permissions` - grants the ObjectPermissions scope
`-m`, `--user_management` - grants the UserManagement scope

### Examples
Create a new user:
```
./eccs -a <uat> createuser -k user
```

## CreateGroup
The base command to create a group on the Encryptonize service is:
```
./eccs -a <uat> creategroup <flags>
```

### Flags

`-r`, `--read` - grants the Read scope
`-c`, `--create` - grants the Create scope
`-u`, `--update` - grants the Update scope
`-i`, `--index` - grants the Index scope
`-p`, `--object_permissions` - grants the ObjectPermissions scope
`-m`, `--user_management` - grants the UserManagement scope

### Examples
Create a new group:
```
./eccs -a <uat> creategroup
```

## AddUserToGroup
The base command to add a user to a group is
```
./eccs -a <uat> addusertogroup <flags>
```

### Flags

`-g`, `--groupid` - group id of the group to add a user to
`-t`, `--target` - the uid of the user to be added to the group

### Examples
Add a user to a group:
```
./eccs -a <uat> addusertogroup -g bf90fe6a-e75a-4ff2-89a2-82c5596a7930 -t 31c7e8e5-15b8-42da-a4ce-9ac812cb0927
```

## RemoveUserFromGroup
The base command to remove a user from a group is
```
./eccs -a <uat> removeuserfromgroup <flags>
```

### Flags

`-g`, `--groupid` - group id of the group to remove a user from
`-t`, `--target` - the uid of the user to be removed from the group

### Examples
Remove a user from a group:
```
./eccs -a <uat> removeuserfromgroup -g bf90fe6a-e75a-4ff2-89a2-82c5596a7930 -t 31c7e8e5-15b8-42da-a4ce-9ac812cb0927
```