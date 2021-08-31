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

package grpce2e

import (
	"bytes"
	"testing"
)

// Test the we can store an object, update and retrieve it later
func TestStoreAndUpdate(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	plaintext := []byte("foo")
	associatedData := []byte("ChunkID")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectId

	newplaintext := []byte("bar")
	newAssociatedData := []byte("ChunkNotID")
	_, err = client.Update(oid, newplaintext, newAssociatedData)
	failOnError("Update operation failed", err, t)

	retrieveResponse, err := client.Retrieve(oid)
	failOnError("Retrieve operation failed", err, t)

	if !bytes.Equal(retrieveResponse.Plaintext, newplaintext) {
		t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse.Plaintext)
	}

	if !bytes.Equal(retrieveResponse.AssociatedData, newAssociatedData) {
		t.Fatalf("Expected associated data %v but got %v", newAssociatedData, retrieveResponse.AssociatedData)
	}
}

func TestStoreAndUpdateWrongOid(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	plaintext := []byte("foo")
	associatedData := []byte("ChunkID")

	_, err = client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := "hello"

	newplaintext := []byte("bar")
	_, err = client.Update(oid, newplaintext, associatedData)
	failOnSuccess("Should not be able to update with a bad oid", err, t)
}

func TestStoreUpdateOtherUserRetrieve(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	plaintext := []byte("foo")
	associatedData := []byte("ChunkID")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)

	oid := storeResponse.ObjectId

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

	// Add the new user to object permission list
	_, err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	client2, err := NewClient(endpoint, uat2, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client2, t)

	plaintext2 := []byte("foo2")

	// Update the object from the new user
	_, err = client2.Update(oid, plaintext2, associatedData)
	failOnError("Store operation failed", err, t)

	// Check that the original user can still retrieve the object
	retrieveResponse2, err := client.Retrieve(oid)
	failOnError("Retrieve operation failed", err, t)

	if !bytes.Equal(retrieveResponse2.Plaintext, plaintext2) {
		t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse2.Plaintext)
	}
}
