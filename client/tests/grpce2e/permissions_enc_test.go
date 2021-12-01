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

//go:build encryption
// +build encryption

package grpce2e

import (
	"testing"

	"context"
	"reflect"

	coreclient "github.com/cyber-crypt-com/encryptonize-core/client"
)

// Test that a user can remove themselves from the object ACL and cannot decrypt the object afterwards
func TestDecryptSameUserWithoutPermissions(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not create client", err, t)

	encResponse, err := client.Encrypt([]byte("foo"), []byte("bar"))
	failOnError("Encrypt operation failed", err, t)
	oid := encResponse.ObjectID

	// Remove self from object ACL
	err = client.RemovePermission(oid, uid)
	failOnError("Removing permissions from self failed", err, t)

	// Try to fetch object without permissions
	_, err = client.Decrypt(oid, encResponse.Ciphertext, encResponse.AssociatedData)
	failOnSuccess("User should not be able to decrypt object with no permissions", err, t)
}

// Test that an encrypted object can be retrieved by another user with permissions
func TestShareEncryptedObjectWithUser(t *testing.T) {
	// Create another user to share the object with
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	// Encrypt an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectID

	// Add another user to object permission list
	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	// Try to retrieve object with another user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Decrypt(oid, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	failOnError("Authorized user could not decrypt object created by another user", err, t)

	// Try to retrieve object with the original user
	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	_, err = client.Decrypt(oid, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	failOnError("Object creator could not decrypt object", err, t)
}

// Test that an encrypted object cannot be
// retrieved by another user without permissions
func TestDecryptWithoutPermissions(t *testing.T) {
	// Create another user to share the object with
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	// Encrypt an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectID

	// Try to retrieve object with another user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Decrypt(oid, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	failOnSuccess("Unauthorized user should not be able to decrypt object", err, t)
}

// Test that granting permission to an object is a transitive operation
// If user A grants access to user B, then user B should be able to grant access to user C
func TestPermissionTransitivityEnc(t *testing.T) {
	// Create admin client for user creation
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not create client", err, t)

	// Create users B and C
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	createUserResponse, err = client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid3 := createUserResponse.UserID
	pwd3 := createUserResponse.Password

	// Encrypt an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectID

	// Grant permissions to user B
	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	// Use user B to grant permissions to user C
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not create client", err, t)

	err = client.AddPermission(oid, uid3)
	failOnError("Add permission request failed", err, t)

	// Check that user C has access to object
	err = client.LoginUser(uid3, pwd3)
	failOnError("Could not create client", err, t)

	_, err = client.Decrypt(oid, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	failOnError("Could not decrypt object", err, t)
}

// Test that any user can get permissions from object
// and that add/remove permission inflicts the outcome of get permissions
func TestGetPermissionsEnc(t *testing.T) {
	// Create admin client for user creation
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create user 2
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	// Encrypt an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectID

	//Check that user 2 cannot get permissions from object, without permissions
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not create client", err, t)

	_, err = client.GetPermissions(oid)
	failOnSuccess("Unauthorized user should not be able to access object permissions", err, t)

	// Grant permissions to user 2
	err = client.LoginUser(uid, pwd)
	failOnError("Could not create client", err, t)

	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	getPermissionsResponse1, err := client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)

	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not create client", err, t)

	getPermissionsResponse2, err := client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)

	// Check that permissions response contains the right gids
	ok := find(getPermissionsResponse1.GroupIDs, uid)
	if !ok {
		t.Fatalf("Couldn't find %v in %v", uid, getPermissionsResponse1.GroupIDs)
	}
	ok = find(getPermissionsResponse1.GroupIDs, uid2)
	if !ok {
		t.Fatalf("Couldn't find %v in %v", uid, getPermissionsResponse1.GroupIDs)
	}

	if !reflect.DeepEqual(getPermissionsResponse1.GroupIDs, getPermissionsResponse2.GroupIDs) {
		t.Fatalf("Permissions aren't the same: %v vs %v", getPermissionsResponse1.GroupIDs, getPermissionsResponse2.GroupIDs)
	}

	// Remove user 2
	err = client.LoginUser(uid, pwd)
	failOnError("Could not create client", err, t)

	err = client.RemovePermission(oid, uid2)
	failOnError("Could not remove permissions", err, t)

	// Check that permissions have been removed
	getPermissionsResponse1, err = client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)
	ok = find(getPermissionsResponse1.GroupIDs, uid)
	if !ok {
		t.Fatalf("Couldn't find %v in %v", uid, getPermissionsResponse1.GroupIDs)
	}
	ok = find(getPermissionsResponse1.GroupIDs, uid2)
	if ok {
		t.Fatalf("Found %v in %v", uid, getPermissionsResponse1.GroupIDs)
	}

	// Check that user 2 doesn't have permissions
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not create client", err, t)

	_, err = client.Decrypt(oid, encryptResponse.Ciphertext, encryptResponse.AssociatedData)
	failOnSuccess("Unauthorized user should not be able to decrypt object", err, t)
}

// Test that permissions cannot be added to a non-existing user
func TestAddPermissionNoTargetUserEnc(t *testing.T) {
	nonExistingUser := "00000000-0000-0000-0000-000000000000"

	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not create client", err, t)

	encryptResponse, err := client.Encrypt([]byte("foo"), []byte("bar"))
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectID

	// Try to add permissions for a non-existing user
	err = client.AddPermission(oid, nonExistingUser)
	failOnSuccess("Shouldn't able to add user that does not exist!", err, t)
}
