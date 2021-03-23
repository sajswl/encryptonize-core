// Copyright 2020 CYBERCRYPT
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
package grpce2e

import (
	"testing"
)

// Tests that we can create and use a user
func TestCreateUser(t *testing.T) {
	client, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)
	t.Logf("%v", createUserResponse)

	// Test user login
	loginUserResponse, err := client.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Login user request failed", err, t)
	t.Logf("%v", loginUserResponse)

	// Test that users can do stuff
	uat2 := loginUserResponse.AccessToken
	if err != nil {
		t.Fatalf("Couldn't parse UAT: %v", err)
	}

	client2, err := NewClient(endpoint, uat2, https)
	failOnError("Could not create client2", err, t)
	defer closeClient(client2, t)

	_, err = client2.Store([]byte("plaintext"), []byte("associatedData"))
	failOnError("Store request failed", err, t)

	// Test admin creation
	createAdminResponse, err := client.CreateUser(protoAdminScopes)
	failOnError("Create admin request failed", err, t)

	// Test admin login
	loginAdminResponse, err := client.LoginUser(createAdminResponse.UserId, createAdminResponse.Password)
	failOnError("Create admin request failed", err, t)

	// Test that created Admin can do stuff
	uatAdmin2 := loginAdminResponse.AccessToken
	clientAdmin2, err := NewClient(endpoint, uatAdmin2, https)
	failOnError("Could not create client2", err, t)
	defer closeClient(clientAdmin2, t)

	// TODO: Whenever remove user is implemented, we should use that here
	_, err = clientAdmin2.CreateUser(protoUserScopes)
	failOnError("Could not create client2", err, t)
}

// Test that wrong UID upon user creation results in an error
func TestCreateUserWrongCredsUID(t *testing.T) {
	// token was edited here            vvvv
	badAT := "bearer ChAAAAAAAAXXXXAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg.47THgf10Vei2v55TGZP-nXpZ7tSWsAYgaDHjAEc1sUA"
	client, err := NewClient(endpoint, badAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation with unauthenticated uid
	_, err = client.CreateUser(protoUserScopes)
	failOnSuccess("User could be created with wrong UID", err, t)
}

// Test that wrongly formatted UID upon user creation results in an error
func TestCreateUserWrongFormatAT(t *testing.T) {
	client, err := NewClient(endpoint, "this_UID_is_not_a_valid_AT", https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation with wrongly formatted
	_, err = client.CreateUser(protoUserScopes)
	failOnSuccess("User could be created with wrongly formatted UID", err, t)
}

// Test that users aren't able to access admin endpoints and vice versa
func TestCreateUserWrongCredsType(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test that users can't access admin endpoints
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnSuccess("User could be created with wrong user type", err, t)
	t.Logf("%v", createUserResponse)

	// Test that admins can't access user endpoints
	clientAdmin, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(clientAdmin, t)

	// create a fresh user which we can add to the access list
	crUserResponse, err := clientAdmin.CreateUser(protoUserScopes)
	failOnError("Could not create second user", err, t)
	uid2 := crUserResponse.UserId

	// Test store
	plaintext := []byte("foo")
	associatedData := []byte("bar")
	_, err = clientAdmin.Store(plaintext, associatedData)
	failOnSuccess("Admin could store object", err, t)
	// Test retrieve
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Couldn't store object", err, t)
	_, err = clientAdmin.Retrieve(storeResponse.ObjectId)
	failOnSuccess("Admin could retrieve object", err, t)
	// Test permissions
	_, err = clientAdmin.GetPermissions(storeResponse.ObjectId)
	failOnSuccess("Admin could get object permissions", err, t)
	_, err = clientAdmin.AddPermission(storeResponse.ObjectId, uid2)
	failOnSuccess("Admin could add object permissions", err, t)
	_, err = clientAdmin.RemovePermission(storeResponse.ObjectId, uid2)
	failOnSuccess("Admin could add object permissions", err, t)
}

func TestRemoveUser(t *testing.T) {
	client, err := NewClient(endpoint, adminAT, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)
	t.Logf("%v", createUserResponse)

	// Test user login
	loginUserResponse, err := client.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnError("Login user request failed", err, t)
	t.Logf("%v", loginUserResponse)

	// Test user removal
	removeUserResponse, err := client.RemoveUser(createUserResponse.UserId)
	failOnError("Remove user request failed", err, t)
	t.Logf("%v", removeUserResponse)

	// Test user login again
	loginUserResponse, err = client.LoginUser(createUserResponse.UserId, createUserResponse.Password)
	failOnSuccess("Login user request suceeded on a deleted user", err, t)
	t.Logf("%v", loginUserResponse)
}
