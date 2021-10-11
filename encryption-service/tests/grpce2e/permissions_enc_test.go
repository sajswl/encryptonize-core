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

//go:build authz && encryption
// +build authz,encryption

package grpce2e

import (
	"reflect"
	"testing"
)

// Test that a user can remove themselves from the object ACL and cannot decrypt the object afterwards
func TestDecryptSameUserWithoutPermissions(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	encResponse, err := client.Encrypt([]byte("foo"), []byte("bar"))
	failOnError("Encrypt operation failed", err, t)
	oid := encResponse.ObjectId

	// Remove self from object ACL
	_, err = client.RemovePermission(oid, uid)
	failOnError("Removing permissions from self failed", err, t)

	// Try to fetch object without permissions
	_, err = client.Decrypt(encResponse.Ciphertext, encResponse.AssociatedData, oid)
	failOnSuccess("User should not be able to decrypt object with no permissions", err, t)
}

// Test that an encrypted object can be retrieved by another user with permissions
func TestShareEncryptedObjectWithUser(t *testing.T) {
	// Create another user to share the object with
	adminClient, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(adminClient, t)

	createUserResponse, err := adminClient.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	loginUserResponse, err := adminClient.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserId
	uat2 := loginUserResponse.AccessToken
	failOnError("Couldn't parse UAT", err, t)

	// Encrypt an object
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectId

	// Add another user to object permission list
	_, err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	// Try to retrieve object with another user
	client2, err := NewClient(endpoint, uat2, https)
	failOnError("Could not create client for new user", err, t)
	defer closeClient(client2, t)
	_, err = client2.Decrypt(encryptResponse.Ciphertext, encryptResponse.AssociatedData, oid)
	failOnError("Authorized user could not decrypt object created by another user", err, t)

	// Try to retrieve object with the original user
	_, err = client.Decrypt(encryptResponse.Ciphertext, encryptResponse.AssociatedData, oid)
	failOnError("Object creator could not decrypt object", err, t)
}

// Test that an encrypted object cannot be
// retrieved by another user without permissions
func TestDecryptWithoutPermissions(t *testing.T) {
	// Create another user to share the object with
	adminClient, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(adminClient, t)

	createUserResponse, err := adminClient.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	loginUserResponse, err := adminClient.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Login user request failed", err, t)

	uat2 := loginUserResponse.AccessToken
	failOnError("Couldn't parse UAT", err, t)

	// Encrypt an object
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectId

	// Try to retrieve object with another user
	client2, err := NewClient(endpoint, uat2, https)
	failOnError("Could not create client for new user", err, t)
	defer closeClient(client2, t)
	_, err = client2.Decrypt(encryptResponse.Ciphertext, encryptResponse.AssociatedData, oid)
	failOnSuccess("Unauthorized user should not be able to decrypt object", err, t)
}

// Test that granting permission to an object is a transitive operation
// If user A grants access to user B, then user B should be able to grant access to user C
func TestPermissionTransitivityEnc(t *testing.T) {
	// Create admin client for user creation
	adminClient, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(adminClient, t)

	// Create users B and C
	createUserResponse, err := adminClient.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	loginUserResponse, err := adminClient.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Login user request failed", err, t)

	uid2 := createUserResponse.UserId
	uat2 := loginUserResponse.AccessToken
	failOnError("Could not parse access token", err, t)

	createUserResponse, err = adminClient.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	loginUserResponse, err = adminClient.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Login user request failed", err, t)

	uid3 := createUserResponse.UserId
	uat3 := loginUserResponse.AccessToken
	failOnError("Could not parse access token", err, t)

	// Encrypt an object
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectId

	// Grant permissions to user B
	_, err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	// Use user B to grant permissions to user C
	client2, err := NewClient(endpoint, uat2, https)
	failOnError("Could not create client2", err, t)
	defer closeClient(client2, t)
	_, err = client2.AddPermission(oid, uid3)
	failOnError("Add permission request failed", err, t)

	// Check that user C has access to object
	client3, err := NewClient(endpoint, uat3, https)
	failOnError("Could not create client3", err, t)
	defer closeClient(client3, t)
	_, err = client3.Decrypt(encryptResponse.Ciphertext, encryptResponse.AssociatedData, oid)
	failOnError("Could not decrypt object", err, t)
}

// Test that any user can get permissions from object
// and that add/remove permission inflicts the outcome of get permissions
func TestGetPermissionsEnc(t *testing.T) {
	// Create admin client for user creation
	adminClient, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(adminClient, t)

	// Create user 2
	createUserResponse, err := adminClient.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	loginUserResponse, err := adminClient.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Login user request failed", err, t)

	uid2 := createUserResponse.UserId
	uat2 := loginUserResponse.AccessToken
	client2, err := NewClient(endpoint, uat2, https)
	failOnError("Could not create client2", err, t)
	defer closeClient(client2, t)

	// Encrypt an object
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectId

	//Check that user 2 cannot get permissions from object, without permissions
	_, err = client2.GetPermissions(oid)
	failOnSuccess("Unauthorized user should not be able to access object permissions", err, t)

	// Grant permissions to user 2
	_, err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	getPermissionsResponse1, err := client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)
	getPermissionsResponse2, err := client2.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)

	// Check that permissions response contains the right uids
	ok := find(getPermissionsResponse1.UserIds, uid)
	if !ok {
		t.Fatalf("Couldn't find %v in %v", uid, getPermissionsResponse1.UserIds)
	}
	ok = find(getPermissionsResponse1.UserIds, uid2)
	if !ok {
		t.Fatalf("Couldn't find %v in %v", uid, getPermissionsResponse1.UserIds)
	}

	if !reflect.DeepEqual(getPermissionsResponse1.UserIds, getPermissionsResponse2.UserIds) {
		t.Fatalf("Permissions aren't the same: %v vs %v", getPermissionsResponse1.UserIds, getPermissionsResponse2.UserIds)
	}

	// Remove user 2
	_, err = client.RemovePermission(oid, uid2)
	failOnError("Could not remove permissions", err, t)

	// Check that permissions have been removed
	getPermissionsResponse1, err = client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)
	ok = find(getPermissionsResponse1.UserIds, uid)
	if !ok {
		t.Fatalf("Couldn't find %v in %v", uid, getPermissionsResponse1.UserIds)
	}
	ok = find(getPermissionsResponse1.UserIds, uid2)
	if ok {
		t.Fatalf("Found %v in %v", uid, getPermissionsResponse1.UserIds)
	}

	// Check that user 2 doesn't have permissions
	_, err = client2.Decrypt(encryptResponse.Ciphertext, encryptResponse.AssociatedData, oid)
	failOnSuccess("Unauthorized user should not be able to decrypt object", err, t)
}

// Test that permissions cannot be added to a non-existing user
func TestAddPermissionNoTargetUserEnc(t *testing.T) {
	nonExistingUser := "00000000-0000-0000-0000-000000000000"

	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	encryptResponse, err := client.Encrypt([]byte("foo"), []byte("bar"))
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectId

	// Try to add permissions for a non-existing user
	_, err = client.AddPermission(oid, nonExistingUser)
	failOnSuccess("Shouldn't able to add user that does not exist!", err, t)
}

// Test that a deleted user can't be added to permissions
func TestAddPermissionsRemovedUserEnc(t *testing.T) {
	// Create admin client for user creation
	adminClient, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(adminClient, t)

	// Create user 2
	createUserResponse, err := adminClient.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	// Encrypt an object
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	encryptResponse, err := client.Encrypt(plaintext, associatedData)
	failOnError("Encrypt operation failed", err, t)
	oid := encryptResponse.ObjectId

	// Test user removal
	_, err = adminClient.RemoveUser(createUserResponse.UserId)
	failOnError("Remove user request failed", err, t)

	// Grant permissions to user 2
	_, err = client.AddPermission(oid, createUserResponse.UserId)
	failOnSuccess("AddPermission should have failed with deleted user", err, t)
}
