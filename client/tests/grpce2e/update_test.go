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

	"bytes"
	"context"

	coreclient "github.com/cyber-crypt-com/encryptonize-core/client"
)

// Test the we can store an object, update and retrieve it later
func TestStoreAndUpdate(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("ChunkID")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectID

	newplaintext := []byte("bar")
	newAssociatedData := []byte("ChunkNotID")
	err = client.Update(oid, newplaintext, newAssociatedData)
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
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("ChunkID")

	_, err = client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := "hello"

	newplaintext := []byte("bar")
	err = client.Update(oid, newplaintext, associatedData)
	failOnSuccess("Should not be able to update with a bad oid", err, t)
}

func TestStoreUpdateOtherUserRetrieve(t *testing.T) {
	client, err := coreclient.NewClient(context.Background(), endpoint, certPath)
	failOnError("Could not create client", err, t)
	defer client.Close()

	err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("ChunkID")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)

	oid := storeResponse.ObjectID

	// Create another user to share the object with
	createUserResponse, err := client.CreateUser(protoUserScopes)
	failOnError("Create user request failed", err, t)

	uid2 := createUserResponse.UserID
	pwd2 := createUserResponse.Password

	// Add the new user to object permission list
	err = client.AddPermission(oid, uid2)
	failOnError("Add permission request failed", err, t)

	plaintext2 := []byte("foo2")

	// Update the object from the new user
	err = client.LoginUser(uid2, pwd2)
	failOnError("Could not log in user", err, t)

	err = client.Update(oid, plaintext2, associatedData)
	failOnError("Store operation failed", err, t)

	// Check that the original user can still retrieve the object
	retrieveResponse2, err := client.Retrieve(oid)
	failOnError("Retrieve operation failed", err, t)

	if !bytes.Equal(retrieveResponse2.Plaintext, plaintext2) {
		t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse2.Plaintext)
	}
}
