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

//go:build encryption && storage
// +build encryption,storage

package grpce2e

import (
	"testing"

	"context"

	coreclient "github.com/cyber-crypt-com/encryptonize-core/client"
)

// Test that unauthorized users cannot perform actions on objects
func TestUnauthorizedAccessToObject(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	// Store an object
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oidStored := storeResponse.ObjectID

	// Encrypt an object
	encResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oidEncrypted := encResponse.ObjectID

	// Create an unauthorized user
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	// Try to use endpoints that require authorization
	_, err = client.Retrieve(oidStored)
	failOnSuccess("Unauthorized user retrieved object", err, t)

	err = client.Update(oidStored, plaintext, associatedData)
	failOnSuccess("Unauthorized user updated object", err, t)

	err = client.Delete(oidStored)
	failOnSuccess("Unauthorized user deleted object", err, t)

	err = client.Update(oidStored, plaintext, associatedData)
	failOnSuccess("Unauthorized user updated object", err, t)

	_, err = client.Decrypt(oidEncrypted, encResponse.Ciphertext, encResponse.AssociatedData)
	failOnSuccess("Unauthorized user decrypted object", err, t)

	_, err = client.GetPermissions(oidStored)
	failOnSuccess("Unauthorized user got permissions", err, t)

	err = client.AddPermission(oidStored, uid)
	failOnSuccess("Unauthorized user added permission", err, t)

	err = client.RemovePermission(oidStored, uid)
	failOnSuccess("Unauthorized user removed permission", err, t)
}

func TestUnauthorizedToRead(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	var scopes = []coreclient.Scope{
		coreclient.ScopeCreate,
		coreclient.ScopeIndex,
		coreclient.ScopeObjectPermissions,
		coreclient.ScopeUserManagement,
		coreclient.ScopeUpdate,
		coreclient.ScopeDelete,
	}

	createUserResponse, err := client.CreateUser(scopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)

	_, err = client.Retrieve(storeResponse.ObjectID)
	failOnSuccess("User should not be able to retrieve object without READ scope", err, t)

	encResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)

	_, err = client.Decrypt(encResponse.ObjectID, encResponse.Ciphertext, associatedData)
	failOnSuccess("User should not be able to decrypt object without READ scope", err, t)
}

func TestUnauthorizedToCreate(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	var scopes = []coreclient.Scope{
		coreclient.ScopeRead,
		coreclient.ScopeIndex,
		coreclient.ScopeObjectPermissions,
		coreclient.ScopeUserManagement,
		coreclient.ScopeUpdate,
		coreclient.ScopeDelete,
	}

	createUserResponse, err := client.CreateUser(scopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	_, err = client.Store(plaintext, associatedData)
	failOnSuccess("User should not be able to store object without CREATE scope", err, t)

	_, err = client.Encrypt(plaintext, associatedData)
	failOnSuccess("User should not be able to encrypt object without CREATE scope", err, t)
}

func TestUnauthorizedToGetPermissions(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	var scopes = []coreclient.Scope{
		coreclient.ScopeRead,
		coreclient.ScopeCreate,
		coreclient.ScopeObjectPermissions,
		coreclient.ScopeUserManagement,
		coreclient.ScopeUpdate,
		coreclient.ScopeDelete,
	}

	createUserResponse, err := client.CreateUser(scopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	storeResponse, err := client.Store([]byte("foo"), []byte("bar"))
	failOnError("Store operation failed", err, t)
	oidStored := storeResponse.ObjectID

	_, err = client.GetPermissions(oidStored)
	failOnSuccess("User should not be able to get permission without INDEX scope", err, t)
}

func TestUnauthorizedToManagePermissions(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	var scopes = []coreclient.Scope{
		coreclient.ScopeRead,
		coreclient.ScopeCreate,
		coreclient.ScopeIndex,
		coreclient.ScopeUserManagement,
		coreclient.ScopeUpdate,
		coreclient.ScopeDelete,
	}

	createUserResponse, err := client.CreateUser(scopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	storeResponse, err := client.Store([]byte("foo"), []byte("bar"))
	failOnError("Store operation failed", err, t)
	oidStored := storeResponse.ObjectID

	err = client.AddPermission(oidStored, uid)
	failOnSuccess("User should not be able to add permission without OBJECTPERMISSIONS scope", err, t)

	err = client.RemovePermission(oidStored, uid)
	failOnSuccess("User should not be able to remove permission without OBJECTPERMISSIONS scope", err, t)
}

func TestUnauthorizedToManageUsers(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	var scopes = []coreclient.Scope{
		coreclient.ScopeRead,
		coreclient.ScopeCreate,
		coreclient.ScopeIndex,
		coreclient.ScopeObjectPermissions,
		coreclient.ScopeUpdate,
		coreclient.ScopeDelete,
	}

	createUserResponse, err := client.CreateUser(scopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	_, err = client.CreateUser(protoUserScopes)
	failOnSuccess("User should not be able to create user without USERMANAGEMENT scope", err, t)
}

func TestUnauthorizedToUpdateAndDelete(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	var scopes = []coreclient.Scope{
		coreclient.ScopeRead,
		coreclient.ScopeCreate,
		coreclient.ScopeIndex,
		coreclient.ScopeObjectPermissions,
		coreclient.ScopeUserManagement,
	}

	createUserResponse, err := client.CreateUser(scopes)
	failOnError("Create user request failed", err, t)

	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	storeResponse, err := client.Store([]byte("foo"), []byte("bar"))
	failOnError("Store operation failed", err, t)
	oidStored := storeResponse.ObjectID

	err = client.Update(oidStored, []byte("new_foo"), []byte("new_bar"))
	failOnSuccess("User should not be able to delete object without UPDATE scope", err, t)

	err = client.Delete(oidStored)
	failOnSuccess("User should not be able to delete object without DELETE scope", err, t)
}
