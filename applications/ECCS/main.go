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
	"fmt"
	"os"
)

func main() {
	if err := InitCmd(); err != nil {
		fmt.Printf(Fail("Unable to initialize CLI: %v\n"), err)
		os.Exit(1)
	}
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf(Fail("%v\n"), err)
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
