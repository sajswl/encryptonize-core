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

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	encryptonize "github.com/cyber-crypt-com/encryptonize-core/client"
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
	Version: "v3.2.0",
	Short:   "ECCS is a simple example client for the Encryptonize encrypted storage solution",
	Args:    cobra.MinimumNArgs(1),
}

// initClient creates a new client with authentication token
func initClient(cmd *cobra.Command, args []string) {
	var err error
	client, err = encryptonize.NewClient(context.Background(), endpoint, certPath)
	if err != nil {
		fmt.Println(Fail(err.Error()))
		os.Exit(1)
	}
	err = client.LoginUser(uid, password)
	if err != nil {
		fmt.Println(Fail(err.Error()))
		os.Exit(1)
	}
}

/////////////////////////////////////////////////////////////////////////
//                           User Management                           //
/////////////////////////////////////////////////////////////////////////

var createUserCmd = &cobra.Command{
	Use:    "createuser",
	Short:  "Creates a user on the server",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		parsedScopes, err := ReadScopes(scopes)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		response, err := client.CreateUser(parsedScopes)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(response)
	},
}

var removeUserCmd = &cobra.Command{
	Use:    "removeuser",
	Short:  "Removes a user from the server",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemoveUser(target); err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
	},
}

var createGroupCmd = &cobra.Command{
	Use:    "creategroup",
	Short:  "Creates a group on the server",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		parsedScopes, err := ReadScopes(scopes)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		response, err := client.CreateGroup(parsedScopes)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(response)
	},
}

var addUserToGroupCmd = &cobra.Command{
	Use:    "addusertogroup",
	Short:  "Adds user to a group",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.AddUserToGroup(target, groupID); err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
	},
}

var removeUserFromGroupCmd = &cobra.Command{
	Use:    "removeuserfromgroup",
	Short:  "Removed user from a group",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.RemoveUserFromGroup(target, groupID); err != nil {
			fmt.Println(Fail(err.Error()))
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
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(response)
	},
}

var decryptCmd = &cobra.Command{
	Use:    "decrypt",
	Short:  "Decrypts data and returns the plaintext",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		associatedDataBytes, err := base64.StdEncoding.DecodeString(associatedData)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		response, err := client.Decrypt(objectID, ciphertextBytes, associatedDataBytes)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(struct {
			Plaintext      string `json:"plaintext"`
			AssociatedData string `json:"associatedData"`
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
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(response)
	},
}

var retrieveCmd = &cobra.Command{
	Use:    "retrieve",
	Short:  "Retrieves your secrets from Encryptonize",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		response, err := client.Retrieve(objectID)
		if err != nil {
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(struct {
			Plaintext      string `json:"plaintext"`
			AssociatedData string `json:"associatedData"`
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
			fmt.Println(Fail(err.Error()))
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
			fmt.Println(Fail(err.Error()))
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
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
		PrintStruct(response)
	},
}

var addPermissionCmd = &cobra.Command{
	Use:    "addpermission",
	Short:  "Adds a user to the permissions list of an object",
	PreRun: initClient,
	Run: func(cmd *cobra.Command, args []string) {
		if err := client.AddPermission(objectID, target); err != nil {
			fmt.Println(Fail(err.Error()))
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
			fmt.Println(Fail(err.Error()))
			os.Exit(1)
		}
	},
}
