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

// Tests that we can create and use a user
func TestCreateUser(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Test user creation
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	// Test user login
	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Login user request failed", err, t)

	// Test that users can do stuff
	_, err = client.Store([]byte("plaintext"), []byte("associatedData"))
	failOnError("Store request failed", err, t)
}

func TestRemoveUser(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Test user creation
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	// Test user login
	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnError("Login user request failed", err, t)

	// Test user removal
	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	err = client.RemoveUser(createUserResponse.UserID)
	failOnError("Remove user request failed", err, t)

	// Test user login again
	err = client.LoginUser(createUserResponse.UserID, createUserResponse.Password)
	failOnSuccess("Login user request succeeded on a deleted user", err, t)
}

func TestRemoveUserNonExisting(t *testing.T) {
	nonExistingUser := "00000000-0000-0000-0000-000000000000"

	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Test user removal
	err = client.RemoveUser(nonExistingUser)
	failOnSuccess("Remove user request succeeded on a non existing user", err, t)
}
