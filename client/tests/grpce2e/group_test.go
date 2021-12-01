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

	coreclient "github.com/cyber-crypt-com/encryptonize-core/client"
)

// Test that we can share an object by adding a group to the access object
func TestShareWithGroup(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Create a group
	createGroupResponse, err := client.CreateGroup(protoUserScopes)
	failOnError("Group creation failed", err, t)
	gid := createGroupResponse.GroupID

	// Create another user, add them to the group
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("User creation failed", err, t)
	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	err = client.AddUserToGroup(uid2, gid)
	failOnError("Adding user to group failed", err, t)

	// Add the group to the access object
	err = client.AddPermission(oid, gid)
	failOnError("Add permission request failed", err, t)

	// Try to retrieve the object as the other user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnError("Retrieving object failed", err, t)
}

// Test that a user with the READ scope in one group cannot access an object if the group that gives
// them access to the object does not have that scope.
func TestGroupScopes(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Create a group with restricted scopes
	createGroupResponse, err := client.CreateGroup([]coreclient.Scope{coreclient.ScopeCreate})
	failOnError("Group creation failed", err, t)
	gid := createGroupResponse.GroupID

	// Create another user with wider scopes, add them to the group
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("User creation failed", err, t)
	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	err = client.AddUserToGroup(uid2, gid)
	failOnError("Adding user to group failed", err, t)

	// Add the group to the access object
	err = client.AddPermission(oid, gid)
	failOnError("Add permission request failed", err, t)

	// Try to retrieve the object as the other user. It should fail as the group that gives them
	// access does not have the read scope.
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnSuccess("Retrieving object was expected to fail", err, t)
}

// Test creation of a group wth invalid scopes
func TestCreateGroupInvalidScopes(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create a group with invalid scopes
	_, err = client.CreateGroup([]coreclient.Scope{42})
	failOnSuccess("Expected group creation to fail", err, t)
}

// Test adding a user to an invalid group
func TestAddUserToGroupInvalidGroup(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Try to add use to an invalid group
	err = client.AddUserToGroup(uid, "6025ea7f-2038-41e0-bc17-aeb2557ded90")
	failOnSuccess("Expected adding user to group to fail", err, t)
}

// Test adding an invalid user to a group
func TestAddUserToGroupInvalidUser(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create a group
	createGroupResponse, err := client.CreateGroup(protoUserScopes)
	failOnError("Group creation failed", err, t)
	gid := createGroupResponse.GroupID

	// Try to add invalid user to the group
	err = client.AddUserToGroup("6025ea7f-2038-41e0-bc17-aeb2557ded90", gid)
	failOnSuccess("Expected adding user to group to fail", err, t)
}

// Test that we can remove a user from a group, stopping them from accessing an object
func TestRemoveUserFromGroup(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Store an object
	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Create a group
	createGroupResponse, err := client.CreateGroup(protoUserScopes)
	failOnError("Group creation failed", err, t)
	gid := createGroupResponse.GroupID

	// Create another user, add them to the group
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("User creation failed", err, t)
	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	err = client.AddUserToGroup(uid2, gid)
	failOnError("Adding user to group failed", err, t)

	// Add the group to the access object
	err = client.AddPermission(oid, gid)
	failOnError("Add permission request failed", err, t)

	// Try to retrieve the object as the other user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	_, err = client.Retrieve(oid)
	failOnError("Retrieving object failed", err, t)

	// Remove the user from the group and check that they no longer have access
	err = client.RemoveUserFromGroup(uid2, gid)
	failOnError("Removing user from group failed", err, t)

	_, err = client.Retrieve(oid)
	failOnSuccess("Expected retrieving object failed", err, t)
}

// Test removing an invalid user from a group
func TestRemoveUserFromGroupInvalidUser(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create a group
	createGroupResponse, err := client.CreateGroup(protoUserScopes)
	failOnError("Group creation failed", err, t)
	gid := createGroupResponse.GroupID

	// Try to remove an invalid user from the group
	err = client.RemoveUserFromGroup("6025ea7f-2038-41e0-bc17-aeb2557ded90", gid)
	failOnSuccess("Expected removing user from group to fail", err, t)
}

// Test that removing a user from a group twice does not fail
func TestRemoveUserFromGroupTwice(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create a group, add user to it
	createGroupResponse, err := client.CreateGroup(protoUserScopes)
	failOnError("Group creation failed", err, t)
	gid := createGroupResponse.GroupID

	err = client.AddUserToGroup(uid, gid)
	failOnError("Adding user to group failed", err, t)

	// Try to remove the user from the group twice
	err = client.RemoveUserFromGroup(uid, gid)
	failOnError("Removing user from group failed", err, t)

	err = client.RemoveUserFromGroup(uid, gid)
	failOnError("Removing user from group failed", err, t)
}

// Test that we can remove a user from their default group
func TestRemoveUserFromDefaultGroup(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Create a user, a default group is automatically created
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("User creation failed", err, t)
	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	// Store an object as the new user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	// Remove user from their default group. They are now a member of no group
	err = client.RemoveUserFromGroup(uid2, uid2)
	failOnError("Removing user from group failed", err, t)

	// They should be unable to access the object
	_, err = client.Retrieve(oid)
	failOnSuccess("Expected retrieving object to fail", err, t)
}
