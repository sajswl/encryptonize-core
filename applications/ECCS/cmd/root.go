// Copyright 2021 CYBERCRYPT
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"eccs/app"
)

// A client instance
var client *app.Client

// Init all flags
var (
	// Common args
	userAT   string
	objectID string
	target   string

	// User ags
	uid      string
	password string

	// Store args
	filename       string
	stdin          bool
	associatedData string

	// CreateUser, CreateGroup args
	scope app.Scope
)

var rootCmd = &cobra.Command{
	Use:     "eccs",
	Version: "v3.1.0",
	Short:   "ECCS is a simple example client for the Encryptonize encrypted storage solution",
	Long: `ECCS is a simple example client for the Encryptonize encrypted storage solution

Environment Variables:
  ECCS_ENDPOINT: The address of the encryption server (e.g. 127.0.0.1:9000)
  ECCS_CRT:      The tls configuration to use with the endpoint. It can be one of four cases:
    - <unset>:                    the server does not use tls (e.g. when using "make docker-up")
    - ECCS_CRT="":                the server uses tls with a trusted root CA
    - ECCS_CRT="$(cat cert.crt)": the server uses the self signed certificate in cert.crt
    - ECCS_CRT="insecure":        the server uses tls but the client will not check the certificate`,
	Args: cobra.MinimumNArgs(1),
}

var storeCmd = &cobra.Command{
	Use:     "store",
	Short:   "Stores your secrets using Encryptonize",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Store(filename, associatedData, stdin); err != nil {
			log.Fatal(err)
		}
	},
}

var retrieveCmd = &cobra.Command{
	Use:     "retrieve",
	Short:   "Retrieves your secrets from Encryptonize",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Retrieve(objectID); err != nil {
			log.Fatal(err)
		}
	},
}

var updateCmd = &cobra.Command{
	Use:     "update",
	Short:   "Updates a stored object and its associated data",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Update(objectID, filename, associatedData, stdin); err != nil {
			log.Fatal(err)
		}
	},
}

var deleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Deletes a stored object",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Delete(objectID); err != nil {
			log.Fatal(err)
		}
	},
}

var getPermissionsCmd = &cobra.Command{
	Use:     "getpermissions",
	Short:   "Gets the permissions of an object",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.GetPermissions(objectID); err != nil {
			log.Fatal(err)
		}
	},
}

var addPermissionCmd = &cobra.Command{
	Use:     "addpermission",
	Short:   "Adds a user to the permissions list of an object",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.AddPermission(objectID, target); err != nil {
			log.Fatal(err)
		}
	},
}

var removePermissionCmd = &cobra.Command{
	Use:     "removepermission",
	Short:   "Removes a user from the permissions list of an object",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemovePermission(objectID, target); err != nil {
			log.Fatal(err)
		}
	},
}

var createUserCmd = &cobra.Command{
	Use:     "createuser",
	Short:   "Creates a user on the server",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.CreateUser(scope); err != nil {
			log.Fatal(err)
		}
	},
}

var loginUserCmd = &cobra.Command{
	Use:     "loginuser",
	Short:   "Logs in with uid and password and prints and access token",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.LoginUser(uid, password); err != nil {
			log.Fatal(err)
		}
	},
}

var removeUserCmd = &cobra.Command{
	Use:     "removeuser",
	Short:   "Removes a user from the serivce",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemoveUser(uid); err != nil {
			log.Fatal(err)
		}
	},
}

var createGroupCmd = &cobra.Command{
	Use:     "creategroup",
	Short:   "Creates a group on the server",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.CreateGroup(scope); err != nil {
			log.Fatal(err)
		}
	},
}

var encryptCmd = &cobra.Command{
	Use:     "encrypt",
	Short:   "Encrypts data and returns the ciphertext",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Encrypt(filename, associatedData, stdin); err != nil {
			log.Fatal(err)
		}
	},
}

var decryptCmd = &cobra.Command{
	Use:     "decrypt",
	Short:   "Decrypts data and returns the plaintext",
	PreRunE: InitClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Decrypt(filename, stdin); err != nil {
			log.Fatal(err)
		}
	},
}

// InitClient creates a new client with authentication token
func InitClient(cmd *cobra.Command, args []string) error {
	var err error
	client, err = app.NewClient(userAT)
	if err != nil {
		return err
	}
	return nil
}

// InitCmd defines commands and flags
func InitCmd() error {
	// Add commands to root
	rootCmd.AddCommand(storeCmd)
	rootCmd.AddCommand(retrieveCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(getPermissionsCmd)
	rootCmd.AddCommand(addPermissionCmd)
	rootCmd.AddCommand(removePermissionCmd)
	rootCmd.AddCommand(createUserCmd)
	rootCmd.AddCommand(loginUserCmd)
	rootCmd.AddCommand(removeUserCmd)
	rootCmd.AddCommand(createGroupCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)

	// Set credential flags
	rootCmd.PersistentFlags().StringVarP(&userAT, "token", "a", "", "User access token")
	if err := rootCmd.MarkPersistentFlagRequired("token"); err != nil {
		return err
	}

	// Set store flags
	storeCmd.Flags().StringVarP(&filename, "filename", "f", "", "File to send to storage")
	storeCmd.Flags().BoolVarP(&stdin, "stdin", "s", false, "Tell ECCS to read from STDIN")
	storeCmd.Flags().StringVarP(&associatedData, "associateddata", "d", "", "Associated data to be stored along with the object")

	// Set retrieve flags
	retrieveCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to retrieve")
	if err := retrieveCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set delete flags
	deleteCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "ID of the object to be deleted")
	if err := retrieveCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set update flags
	updateCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "ID of the object to be updated")
	if err := updateCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}
	updateCmd.Flags().StringVarP(&filename, "filename", "f", "", "File with updated data")
	updateCmd.Flags().BoolVarP(&stdin, "stdin", "s", false, "Read updated data from STDIN")
	updateCmd.Flags().StringVarP(&associatedData, "associateddata", "d", "", "Updated associated data to be stored along with the object")

	// Set getPermissions flags
	getPermissionsCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to get permissions from")
	if err := getPermissionsCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set addPermission flags
	addPermissionCmd.Flags().StringVarP(&target, "target", "t", "", "Target UID to add to permission list of object")
	if err := addPermissionCmd.MarkFlagRequired("target"); err != nil {
		return err
	}
	addPermissionCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to add permissions to")
	if err := addPermissionCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set removePermission flags
	removePermissionCmd.Flags().StringVarP(&target, "target", "t", "", "Target UID to remove from permissions list of object")
	if err := removePermissionCmd.MarkFlagRequired("target"); err != nil {
		return err
	}
	removePermissionCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to remove permissions from")
	if err := removePermissionCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set createUser flags
	createUserCmd.Flags().BoolVarP(&scope.Read, "read", "r", false, "Grants the Read scope to the newly created user")
	createUserCmd.Flags().BoolVarP(&scope.Create, "create", "c", false, "Grants the Create scope to the newly created user")
	createUserCmd.Flags().BoolVarP(&scope.Update, "update", "u", false, "Grants the Update scope to the newly created user")
	createUserCmd.Flags().BoolVarP(&scope.Delete, "delete", "d", false, "Grants the Delete scope to the newly created user")
	createUserCmd.Flags().BoolVarP(&scope.Index, "index", "i", false, "Grants the Index scope to the newly created user")
	createUserCmd.Flags().BoolVarP(&scope.ObjectPermissions, "object_permissions", "p", false, "Grants the ObjectPermissions scope to the newly created user")
	createUserCmd.Flags().BoolVarP(&scope.UserManagement, "user_management", "m", false, "Grants the UserManagement scope to the newly created user")

	// Set loginUser flags
	loginUserCmd.Flags().StringVarP(&uid, "uid", "u", "", "UID of the user to retrieve a token for")
	loginUserCmd.Flags().StringVarP(&password, "password", "p", "", "Password of the provided user")

	// Set removeUser flags
	removeUserCmd.Flags().StringVarP(&uid, "target", "t", "", "Target UID of the user to be removed")

	// Set createGroup flags
	createGroupCmd.Flags().BoolVarP(&scope.Read, "read", "r", false, "Grants the Read scope to the newly created group")
	createGroupCmd.Flags().BoolVarP(&scope.Create, "create", "c", false, "Grants the Create scope to the newly created group")
	createGroupCmd.Flags().BoolVarP(&scope.Update, "update", "u", false, "Grants the Update scope to the newly created group")
	createGroupCmd.Flags().BoolVarP(&scope.Delete, "delete", "d", false, "Grants the Delete scope to the newly created group")
	createGroupCmd.Flags().BoolVarP(&scope.Index, "index", "i", false, "Grants the Index scope to the newly created group")
	createGroupCmd.Flags().BoolVarP(&scope.ObjectPermissions, "object_permissions", "p", false, "Grants the ObjectPermissions scope to the newly created group")
	createGroupCmd.Flags().BoolVarP(&scope.UserManagement, "user_management", "m", false, "Grants the UserManagement scope to the newly created group")

	// Set encrypt flags
	encryptCmd.Flags().BoolVarP(&stdin, "stdin", "s", false, "Tell ECCS to read from STDIN")
	encryptCmd.Flags().StringVarP(&filename, "filename", "f", "", "File to be encrypted")
	encryptCmd.Flags().StringVarP(&associatedData, "associateddata", "d", "", "Associated data to be used for object authentication")

	// Set decrypt flags
	decryptCmd.Flags().BoolVarP(&stdin, "stdin", "s", false, "Tell ECCS to read from STDIN")
	decryptCmd.Flags().StringVarP(&filename, "filename", "f", "", "File containing encrypted data")

	return nil
}

// Execute runs the parser for the command line arguments
func Execute() error {
	return rootCmd.Execute()
}
