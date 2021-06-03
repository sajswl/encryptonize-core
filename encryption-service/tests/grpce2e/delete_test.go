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
	"testing"
)

// Test the we can store an object and delete it later
func TestStoreDeleteRetrieve(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectId
	_, err = client.Delete(oid)
	failOnError("Delete operation failed", err, t)

	_, err = client.Retrieve(oid)
	failOnSuccess("Object is retrievable after delete", err, t)
}

func TestStoreDeleteTwice(t *testing.T) {
	client, err := NewClient(endpoint, uat, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectId
	_, err = client.Delete(oid)
	failOnError("Delete operation failed", err, t)

	// The endpoint should not return an error if the OID does not exist
	_, err = client.Delete(oid)
	failOnError("Delete operation failed because OID doesn't exist", err, t)
}