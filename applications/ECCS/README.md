# Encryptonize Core Cloud Storage 3.1.0

Encryptonize Core Cloud Storage is an example of an easy to use CLI tool for storing secrets with
the Encryptonize solution. It is essentially a thin CLI wrapper of the Encryptonize client library.
It is ment as a starting point / code example for developers who want to interact with Encryptonize.

## Compilation
You will need to have `go` installed on your system. Instructions on installing go can be found
[HERE](https://golang.org/doc/install). To compile the application, simply run
```
make build
```

## Usage

You will need user credentials (UID and password) for an existing Encryptonize user. For information
on how to create users, see the [User Manual](../../documentation/manuals/user_manual.md). ECCS will
automatically retrieve and use a new access token for each call to Encryptonize.

You can retrieve the following help message for ECCS by running `./eccs -h`:
```
ECCS is a simple example client for the Encryptonize encrypted storage solution

Usage:
  eccs [command]

Available Commands:
  addpermission       Adds a user to the permissions list of an object
  addusertogroup      Adds user to a group
  completion          generate the autocompletion script for the specified shell
  creategroup         Creates a group on the server
  createuser          Creates a user on the server
  decrypt             Decrypts data and returns the plaintext
  delete              Deletes a stored object
  encrypt             Encrypts data and returns the ciphertext
  getpermissions      Gets the permissions of an object
  help                Help about any command
  removepermission    Removes a user from the permissions list of an object
  removeuser          Removes a user from the server
  removeuserfromgroup Removed user from a group
  retrieve            Retrieves your secrets from Encryptonize
  store               Stores your secrets using Encryptonize
  update              Updates a stored object and its associated data

Flags:
  -c, --certpath string   Path to Encryptonize certificate
  -e, --endpoint string   Encryptonize endpoint (default "localhost:9000")
  -h, --help              help for eccs
  -p, --password string   Password
  -u, --uid string        User ID
  -v, --version           version for eccs

Use "eccs [command] --help" for more information about a command.
```

All responses are output to standard out in JSON format.

### Global Flags

The following flag applies to all commands. In particular you will need to set `--uid` and
`--password` to use ECCS.

| Flag         | Shorthand | Description                                                     |
| ---          | ---       | ---                                                             |
| `--uid`      | `-u`      | User ID                                                         |
| `--password` | `-p`      | User password                                                   |
| `--endpoint` | `-e`      | Endpoint of the Encryptonize service (default `localhost:9000`) |
| `--certpath` | `-c`      | Path to a TLS certificate for the service. Enables TLS if set   |

