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

//go:build storage
// +build storage

package grpce2e

import (
	"testing"

	"context"
	"reflect"

	coreclient "github.com/cyber-crypt-com/encryptonize-core/client"
)

// Test that a user can remove themselves from the object ACL and cannot access the object afterwards
func TestRetrieveSameUserWithoutPermissions(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	storeResponse, err := client.Store([]byte("foo"), []byte("bar"))
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Remove self from object ACL
	err = client.RemovePermission(oid, uid)
	failOnError("Removing permissions from self failed", err, t)

	// Try to fetch object without permissions
	_, err = client.Retrieve(oid)
	failOnSuccess("User should not be able to retrieve object with no permissions", err, t)
}

// Test that a stored object can be retrieved by another user with permissions
func TestShareObjectWithUser(t *testing.T) {
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

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Add another user to object permission list
	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	// Try to retrieve object with another user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnError("Authorized user could not fetch object created by another user", err, t)

	// Try to retrieve object with the original user
	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnError("Object creator could not fetch object", err, t)
}

// Test that a stored object cannot be retrieved by another user without permissions
func TestRetrieveWithoutPermissions(t *testing.T) {
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

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Try to retrieve object with another user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnSuccess("Unauthorized user should not be able to access object", err, t)
}

// Test that granting permission to an object is a transitive operation
// If user A grants access to user B, then user B should be able to grant access to user C
func TestPermissionTransitivity(t *testing.T) {
	// Create admin client for user creation
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create users B and C
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	createUserResponse, err = client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid3 := createUserResponse.UserID
	pwd3 := createUserResponse.Password

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Grant permissions to user B
	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	// Use user B to grant permissions to user C
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	err = client.AddPermission(oid, uid3)
	failOnError("Add permission request failed", err, t)

	// Check that user C has access to object
	err = client.LoginUser(uid3, pwd3)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnError("Could not retrieve object", err, t)
}

// Test that any user can get permissions from object
// and that add/remove permission inflicts the outcome of get permissions
func TestGetPermissions(t *testing.T) {
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

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	//Check that user 2 cannot get permissions from object, without permissions
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.GetPermissions(oid)
	failOnSuccess("Unauthorized user should not be able to access object permissions", err, t)

	// Grant permissions to user 2
	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	getPermissionsResponse1, err := client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)

	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	getPermissionsResponse2, err := client.GetPermissions(oid)
	failOnError("Could not get permissions", err, t)

	// Check that permissions response contains the right uids
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
	failOnError("Could not log in user", err, t)

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
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnSuccess("Unauthorized user should not be able to access object", err, t)
}

// Test that permissions cannot be added to a non-existing user
func TestAddPermissionNoTargetUser(t *testing.T) {
	nonExistingUser := "00000000-0000-0000-0000-000000000000"

	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	storeResponse, err := client.Store([]byte("foo"), []byte("bar"))
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Try to add permissions for a non-existing user
	err = client.AddPermission(oid, nonExistingUser)
	failOnSuccess("Shouldn't able to add user that does not exist!", err, t)
}
