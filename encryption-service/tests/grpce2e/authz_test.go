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

//go:build authz && encryption && storage
// +build authz,encryption,storage

package grpce2e

import (
	"testing"
)

// Test that unauthorized users cannot perform actions on objects
func TestUnauthorizedAccess(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	// Store an object
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oidStored := storeResponse.ObjectId

	// Encrypt an object
	encResponse, err := client.Encrypt([]byte("foo"), []byte("bar"))
	failOnError("Encrypt operation failed", err, t)
	oidEncrypted := encResponse.ObjectId

	// Create an unauthorized user
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	_, err = client.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Could not log in user", err, t)

	// Try to use endpoints that require authorization
	_, err = client.Retrieve(oidStored)
	failOnSuccess("Unauthorized user retrieved object", err, t)

	_, err = client.Update(oidStored, plaintext, associatedData)
	failOnSuccess("Unauthorized user updated object", err, t)

	_, err = client.Delete(oidStored)
	failOnSuccess("Unauthorized user deleted object", err, t)

	_, err = client.Update(oidStored, plaintext, associatedData)
	failOnSuccess("Unauthorized user updated object", err, t)

	_, err = client.Decrypt(encResponse.Ciphertext, encResponse.AssociatedData, oidEncrypted)
	failOnSuccess("Unauthorized user decrypted object", err, t)

	_, err = client.GetPermissions(oidStored)
	failOnSuccess("Unauthorized user got permissions", err, t)

	_, err = client.AddPermission(oidStored, uid)
	failOnSuccess("Unauthorized user added permission", err, t)

	_, err = client.RemovePermission(oidStored, uid)
	failOnSuccess("Unauthorized user removed permission", err, t)
}
