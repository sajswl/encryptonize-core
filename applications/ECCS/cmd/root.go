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
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	encryptonize "client"
	"eccs/utils"
)

// A client instance
var client *encryptonize.Client

// Init all flags
var (
	// Client args
	endpoint string
	certPath string

	// Request args
	scopes         string
	userID         string
	groupID        string
	target         string
	objectID       string
	plaintext      string
	ciphertext     string
	associatedData string

	// User ags
	uid      string
	password string
)

var rootCmd = &cobra.Command{
	Use:     "eccs",
	Version: "v3.1.0",
	Short:   "ECCS is a simple example client for the Encryptonize encrypted storage solution",
	Args:    cobra.MinimumNArgs(1),
}

/////////////////////////////////////////////////////////////////////////
//                           User Management                           //
/////////////////////////////////////////////////////////////////////////

var createUserCmd = &cobra.Command{
	Use:    "createuser",
	Short:  "Creates a user on the server",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		parsedScopes, err := utils.ReadScopes(scopes)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		response, err := client.CreateUser(parsedScopes)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(response)
	},
}

var removeUserCmd = &cobra.Command{
	Use:    "removeuser",
	Short:  "Removes a user from the server",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemoveUser(target); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

var createGroupCmd = &cobra.Command{
	Use:    "creategroup",
	Short:  "Creates a group on the server",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		parsedScopes, err := utils.ReadScopes(scopes)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		response, err := client.CreateGroup(parsedScopes)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(response)
	},
}

var addUserToGroupCmd = &cobra.Command{
	Use:    "addusertogroup",
	Short:  "Adds user to a group",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.AddUserToGroup(userID, groupID); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

var removeUserFromGroupCmd = &cobra.Command{
	Use:    "removeuserfromgroup",
	Short:  "Removed user from a group",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemoveUserFromGroup(userID, groupID); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

/////////////////////////////////////////////////////////////////////////
//                              Encryption                             //
/////////////////////////////////////////////////////////////////////////

var encryptCmd = &cobra.Command{
	Use:    "encrypt",
	Short:  "Encrypts data and returns the ciphertext",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		response, err := client.Encrypt([]byte(plaintext), []byte(associatedData))
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(response)
	},
}

var decryptCmd = &cobra.Command{
	Use:    "decrypt",
	Short:  "Decrypts data and returns the plaintext",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		associatedDataBytes, err := base64.StdEncoding.DecodeString(associatedData)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		response, err := client.Decrypt(objectID, ciphertextBytes, associatedDataBytes)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(struct {
			Plaintext      string
			AssociatedData string
		}{
			string(response.Plaintext),
			string(response.AssociatedData),
		})
	},
}

/////////////////////////////////////////////////////////////////////////
//                               Storage                               //
/////////////////////////////////////////////////////////////////////////

var storeCmd = &cobra.Command{
	Use:    "store",
	Short:  "Stores your secrets using Encryptonize",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		response, err := client.Store([]byte(plaintext), []byte(associatedData))
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(response)
	},
}

var retrieveCmd = &cobra.Command{
	Use:    "retrieve",
	Short:  "Retrieves your secrets from Encryptonize",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		response, err := client.Retrieve(objectID)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(struct {
			Plaintext      string
			AssociatedData string
		}{
			string(response.Plaintext),
			string(response.AssociatedData),
		})
	},
}

var updateCmd = &cobra.Command{
	Use:    "update",
	Short:  "Updates a stored object and its associated data",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Update(objectID, []byte(plaintext), []byte(associatedData)); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

var deleteCmd = &cobra.Command{
	Use:    "delete",
	Short:  "Deletes a stored object",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.Delete(objectID); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

/////////////////////////////////////////////////////////////////////////
//                             Permissions                             //
/////////////////////////////////////////////////////////////////////////

var getPermissionsCmd = &cobra.Command{
	Use:    "getpermissions",
	Short:  "Gets the permissions of an object",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		response, err := client.GetPermissions(objectID)
		if err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
		utils.PrintStruct(response)
	},
}

var addPermissionCmd = &cobra.Command{
	Use:    "addpermission",
	Short:  "Adds a user to the permissions list of an object",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.AddPermission(objectID, target); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

var removePermissionCmd = &cobra.Command{
	Use:    "removepermission",
	Short:  "Removes a user from the permissions list of an object",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemovePermission(objectID, target); err != nil {
			fmt.Println(utils.Fail(err.Error()))
			os.Exit(1)
		}
	},
}

// initClient creates a new client with authentication token
func initClient(cmd *cobra.Command, args []string) {
	var err error
	client, err = encryptonize.NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		fmt.Println(utils.Fail(err.Error()))
		os.Exit(1)
	}
	err = client.LoginUser(uid, password)
	if err != nil {
		fmt.Println(utils.Fail(err.Error()))
		os.Exit(1)
	}
}

// InitCmd defines commands and flags
func InitCmd() error {
	// Set root flags
	rootCmd.PersistentFlags().StringVarP(&uid, "uid", "u", "", "User ID")
	if err := rootCmd.MarkPersistentFlagRequired("uid"); err != nil {
		return err
	}
	rootCmd.PersistentFlags().StringVarP(&password, "password", "p", "", "Password")
	if err := rootCmd.MarkPersistentFlagRequired("password"); err != nil {
		return err
	}
	rootCmd.PersistentFlags().StringVarP(&endpoint, "endpoint", "e", "localhost:9000", "Encryptonize endpoint")
	rootCmd.PersistentFlags().StringVarP(&certPath, "certpath", "c", "", "Path to Encryptonize certificate")

	/////////////////////////////////////////////////////////////////////////
	//                           User Management                           //
	/////////////////////////////////////////////////////////////////////////
	rootCmd.AddCommand(createUserCmd)
	rootCmd.AddCommand(removeUserCmd)
	rootCmd.AddCommand(createGroupCmd)
	rootCmd.AddCommand(addUserToGroupCmd)
	rootCmd.AddCommand(removeUserFromGroupCmd)

	// Set createUser flags
	createUserCmd.Flags().StringVarP(&scopes, "scopes", "s", "", "Which scopes to grant [rcudiom]")

	// Set removeUser flags
	removeUserCmd.Flags().StringVarP(&target, "target", "t", "", "Target UID of the user to be removed")
	if err := removeUserCmd.MarkFlagRequired("target"); err != nil {
		return err
	}

	// Set createGroup flags
	createGroupCmd.Flags().StringVarP(&scopes, "scopes", "s", "", "Which scopes to grant [rcudiom]")

	// Set addUserToGroup flags
	addUserToGroupCmd.Flags().StringVarP(&target, "target", "t", "", "UID of the user to be added to a group")
	if err := addUserToGroupCmd.MarkFlagRequired("target"); err != nil {
		return err
	}
	addUserToGroupCmd.Flags().StringVarP(&groupID, "groupid", "g", "", "GroupID of the group to add user to")
	if err := addUserToGroupCmd.MarkFlagRequired("groupid"); err != nil {
		return err
	}

	// Set removeUserFromGroup flags
	removeUserFromGroupCmd.Flags().StringVarP(&target, "target", "t", "", "UID of the user to be removed from a group")
	if err := removeUserFromGroupCmd.MarkFlagRequired("target"); err != nil {
		return err
	}
	removeUserFromGroupCmd.Flags().StringVarP(&groupID, "groupid", "g", "", "GroupID of the group to remove user from")
	if err := removeUserFromGroupCmd.MarkFlagRequired("groupid"); err != nil {
		return err
	}

	/////////////////////////////////////////////////////////////////////////
	//                              Encryption                             //
	/////////////////////////////////////////////////////////////////////////
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)

	// Set encrypt flags
	encryptCmd.Flags().StringVarP(&plaintext, "plaintext", "d", "", "Plaintext data to be encrypted")
	encryptCmd.Flags().StringVarP(&associatedData, "associateddata", "a", "", "Associated data to be used for object authentication")

	// Set decrypt flags
	decryptCmd.Flags().StringVarP(&ciphertext, "ciphertext", "d", "", "ciphertext data to be decrypted")
	decryptCmd.Flags().StringVarP(&associatedData, "associateddata", "a", "", "Associated data to be used for object authentication")
	decryptCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to retrieve")
	if err := decryptCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	/////////////////////////////////////////////////////////////////////////
	//                               Storage                               //
	/////////////////////////////////////////////////////////////////////////
	rootCmd.AddCommand(storeCmd)
	rootCmd.AddCommand(retrieveCmd)
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(deleteCmd)

	// Set store flags
	storeCmd.Flags().StringVarP(&plaintext, "plaintext", "d", "", "Plaintext data to be encrypted")
	storeCmd.Flags().StringVarP(&associatedData, "associateddata", "a", "", "Associated data to be used for object authentication")

	// Set retrieve flags
	retrieveCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to retrieve")
	if err := retrieveCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set update flags
	updateCmd.Flags().StringVarP(&plaintext, "plaintext", "d", "", "Plaintext data to be encrypted")
	updateCmd.Flags().StringVarP(&associatedData, "associateddata", "a", "", "Associated data to be used for object authentication")
	updateCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "ID of the object to be updated")
	if err := updateCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set delete flags
	deleteCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "ID of the object to be deleted")
	if err := retrieveCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	/////////////////////////////////////////////////////////////////////////
	//                             Permissions                             //
	/////////////////////////////////////////////////////////////////////////
	rootCmd.AddCommand(getPermissionsCmd)
	rootCmd.AddCommand(addPermissionCmd)
	rootCmd.AddCommand(removePermissionCmd)

	// Set getPermissions flags
	getPermissionsCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to get permissions from")
	if err := getPermissionsCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set addPermission flags
	addPermissionCmd.Flags().StringVarP(&target, "target", "t", "", "Target ID to add to permission list of object")
	if err := addPermissionCmd.MarkFlagRequired("target"); err != nil {
		return err
	}
	addPermissionCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to add permissions to")
	if err := addPermissionCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	// Set removePermission flags
	removePermissionCmd.Flags().StringVarP(&target, "target", "t", "", "Target ID to remove from permissions list of object")
	if err := removePermissionCmd.MarkFlagRequired("target"); err != nil {
		return err
	}
	removePermissionCmd.Flags().StringVarP(&objectID, "objectid", "o", "", "Object ID of file to remove permissions from")
	if err := removePermissionCmd.MarkFlagRequired("objectid"); err != nil {
		return err
	}

	return nil
}

// Execute runs the parser for the command line arguments
func Execute() error {
	return rootCmd.Execute()
}
