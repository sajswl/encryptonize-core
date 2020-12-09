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

	"encryption-service/app"
)

// Tests that we can create and use a user
func TestCreateUser(t *testing.T) {
	client, err := NewClient(endpoint, uidAdmin, uatAdmin, scopesAdmin, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation
	userType := app.CreateUserRequest_USER
	createUserResponse, err := client.CreateUser(userType)
	failOnError("Create user request failed", err, t)
	t.Logf("%v", createUserResponse)

	// Test that users can do stuff
	uid2 := createUserResponse.UserID
	uat2 := createUserResponse.AccessToken
	if err != nil {
		t.Fatalf("Couldn't parse UAT: %v", err)
	}

	client2, err := NewClient(endpoint, uid2, uat2, scopesUser, https)
	failOnError("Could not create client2", err, t)
	defer closeClient(client2, t)

	_, err = client2.Store([]byte("plaintext"), []byte("associatedData"))
	failOnError("Store request failed", err, t)

	// Test admin creation
	userType = app.CreateUserRequest_ADMIN
	createAdminResponse, err := client.CreateUser(userType)
	failOnError("Create admin request failed", err, t)
	// Test that created Admin can do stuff
	uidAdmin2 := createAdminResponse.UserID
	uatAdmin2 := createAdminResponse.AccessToken
	clientAdmin2, err := NewClient(endpoint, uidAdmin2, uatAdmin2, scopesAdmin, https)
	failOnError("Could not create client2", err, t)
	defer closeClient(clientAdmin2, t)

	// TODO: Whenever remove user is implemented, we should use that here
	userType = app.CreateUserRequest_USER
	_, err = clientAdmin2.CreateUser(userType)
	failOnError("Could not create client2", err, t)
}

// Test that wrong UID upon user creation results in an error
func TestCreateUserWrongCredsUID(t *testing.T) {
	client, err := NewClient(endpoint, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", uatAdmin, scopesAdmin, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation with unauthenticated uid
	userType := app.CreateUserRequest_USER
	_, err = client.CreateUser(userType)
	failOnSuccess("User could be created with wrong UID", err, t)
}

// Test that wrongly formatted UID upon user creation results in an error
func TestCreateUserWrongFormatUID(t *testing.T) {
	client, err := NewClient(endpoint, "this_UID_is_not_a_valid_UUID", uatAdmin, scopesAdmin, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation with wrongly formatted
	userType := app.CreateUserRequest_USER
	_, err = client.CreateUser(userType)
	failOnSuccess("User could be created with wrongly formatted UID", err, t)
}

// Test that wrong UAT upon user creation results in an error
func TestCreateUserWrongCredsUAT(t *testing.T) {
	client, err := NewClient(endpoint, uidAdmin, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", scopesAdmin, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation
	userType := app.CreateUserRequest_USER
	_, err = client.CreateUser(userType)
	failOnSuccess("User could be created with wrong UAT", err, t)
}

// Test that wrongly formatted UAT upon user creation results in an error
func TestCreateUserWrongFormatUAT(t *testing.T) {
	client, err := NewClient(endpoint, uidAdmin, "this_is_not_valid_hex_or_a_valid_token", scopesAdmin, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test user creation
	userType := app.CreateUserRequest_USER
	_, err = client.CreateUser(userType)
	failOnSuccess("User could be created with wrongly formatted UAT", err, t)
}

// Test that users aren't able to access admin endpoints and vice versa
func TestCreateUserWrongCredsType(t *testing.T) {
	client, err := NewClient(endpoint, uid, uat, scopesUser, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	// Test that users can't access admin endpoints
	userType := app.CreateUserRequest_USER
	createUserResponse, err := client.CreateUser(userType)
	failOnSuccess("User could be created with wrong user type", err, t)
	t.Logf("%v", createUserResponse)

	// Test that admins can't access user endpoints
	clientAdmin, err := NewClient(endpoint, uidAdmin, uatAdmin, scopesAdmin, https)
	failOnError("Could not create client", err, t)
	defer closeClient(clientAdmin, t)

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
	_, err = clientAdmin.AddPermission(storeResponse.ObjectId, uidAdmin)
	failOnSuccess("Admin could add object permissions", err, t)
	_, err = clientAdmin.RemovePermission(storeResponse.ObjectId, uidAdmin)
	failOnSuccess("Admin could add object permissions", err, t)
}
