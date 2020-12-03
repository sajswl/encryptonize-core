# Encryptonize Core Cloud Storage

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

The following flags apply to all commands:

`-u`, `--user` - user ID

`-a`, `--token` - user access token

## Store
The base command for storage is
```
./eccs store <flags>
```

### Flags

`-f`, `--filename` - path to the file to be stored

`-s`, `--stdin` - read directly from `STDIN`

`-a`, `--associateddata` - Associated data to be stored along with the object

### Examples
Store file:
```
./eccs -u <uid> -a <uat> store -f ./super_secret_document.pdf
```
Store file with associated data:
```
./eccs -u <uid> -a <uat> store -f ./super_secret_document.pdf -a "index1:someData1,index2:someMoreData"
```

Store from `STDIN`:
```
echo "In case of fire: git commit; git push" | ./eccs -u <uid> -a <uat> store -s
```

## Retrieve
The base command for retrieve is
```
./eccs -u <uid> -a <uat> retrieve <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to be retrieved

### Examples
Retrieve file:
```
./eccs -u <uid> -a <uat> retrieve -o 36ccd006-c063-4765-a909-ad398dbfd413
```

## GetPermissions
The base command to get permissions for an object is
```
./eccs -u <uid> -a <uat> getpermissions <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to get permissions list from

### Examples
Get permissions list of a file:
```
./eccs -u <uid> -a <uat> getpermissions -o 36ccd006-c063-4765-a909-ad398dbfd413
```

## AddPermission
The base command to add a permission to an object is
```
./eccs -u <uid> -a <uat> addpermission <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to add a permission to
`-t`, `--target` - the uid of the user to add to the permissions list

### Examples
Add a permission to a file:
```
./eccs -u <uid> -a <uat> addpermission -o 36ccd006-c063-4765-a909-ad398dbfd413 -t 31c7e8e5-15b8-42da-a4ce-9ac812cb0927
```

## RemovePermission
The base command to remove a permission from an object is
```
./eccs -u <uid> -a <uat> removepermission <flags>
```

### Flags

`-o`, `--objectid` - object id of the file to remove a permission from
`-t`, `--target` - the uid of the user to remove from the permissions list

### Examples
Remove a permission to a file:
```
./eccs -u <uid> -a <uat> removepermission -o 36ccd006-c063-4765-a909-ad398dbfd413 -t 31c7e8e5-15b8-42da-a4ce-9ac812cb0927
```

## CreateUser
The base command to create a user on the Encryptonize service is:
```
./eccs -u <uid> -a <uat> createuser <flags>
```
Keep in mind that to create a user, the credentials supplied via `ECCS_UID` and `ECCS_UAT` must be admin credentials.

### Flags

`-u`, `--userkind` - the kind of user to be created

### Examples
Create a new user:
```
./eccs -u <uid> -a <uat> createuser -u user
```
