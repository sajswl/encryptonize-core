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
	"bytes"
	"fmt"
	"sync"
	"testing"
	"testing/quick"

	"encryption-service/impl/crypt"
)

// Test the we can store an object and retrieve it later
func TestStoreAndRetrieve(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectId
	retrieveResponse, err := client.Retrieve(oid)
	failOnError("Retrieve operation failed", err, t)

	if !bytes.Equal(retrieveResponse.Plaintext, plaintext) {
		t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse.Plaintext)
	}

	if !bytes.Equal(retrieveResponse.AssociatedData, associatedData) {
		t.Fatalf("Expected associated data %v but got %v", associatedData, retrieveResponse.AssociatedData)
	}
}

// Test that we can store the same object/data multiple times and still retrieve it
func TestStoreSameObjectMultipleTimes(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	for i := 0; i < 5; i++ {
		storeResponse, err := client.Store(plaintext, associatedData)
		failOnError("Store operation failed", err, t)
		oid := storeResponse.ObjectId
		retrieveResponse, err := client.Retrieve(oid)
		failOnError("Retrieve operation failed", err, t)

		if !bytes.Equal(retrieveResponse.Plaintext, plaintext) {
			t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse.Plaintext)
		}

		if !bytes.Equal(retrieveResponse.AssociatedData, associatedData) {
			t.Fatalf("Expected associated data %v but got %v", associatedData, retrieveResponse.AssociatedData)
		}
	}
}

// Test retrieving object with invalid oid
func TestRetrieveBadOid(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	oid := "bad"
	_, err = client.Retrieve(oid)
	failOnSuccess("Should not be able to retrieve antyhing with a bad oid", err, t)
}

// Test multiple retrieve operations of the same object
func TestMultipleStoreRetrieve(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	plaintext := []byte("foo")
	associatedData := []byte("bar")

	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectId

	// Retrieve the object multiple times
	for i := 0; i < 10; i++ {
		retrieveResponse, err := client.Retrieve(oid)
		failOnError("Retrieve operation failed", err, t)

		if !bytes.Equal(retrieveResponse.Plaintext, plaintext) {
			t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse.Plaintext)
		}

		if !bytes.Equal(retrieveResponse.AssociatedData, associatedData) {
			t.Fatalf("Expected associated data %v but got %v", associatedData, retrieveResponse.AssociatedData)
		}
	}
}

// Test that an older object can be retrieved after storing multiple objects.
func TestRetrieveOlderObject(t *testing.T) {
	client, err := NewClient(endpoint, https)
	defer closeClient(client, t)
	failOnError("Could not create client", err, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	// Store first object
	plaintext := []byte("foo1")
	associatedData := []byte("bar1")
	storeResponse, err := client.Store(plaintext, associatedData)
	failOnError("Could not create first object", err, t)
	oid := storeResponse.ObjectId

	// Store some other objects
	plaintext2 := []byte("foo2")
	associatedData2 := []byte("bar2")
	storeResponse2, err := client.Store(plaintext2, associatedData2)
	failOnError("Could not create second object", err, t)
	_, err = client.Retrieve(storeResponse2.ObjectId)
	failOnError("Could not retrieve object", err, t)
	plaintext3 := []byte("foo3")
	associatedData3 := []byte("bar3")
	storeResponse3, err := client.Store(plaintext3, associatedData3)
	failOnError("Could not create third object", err, t)
	_, err = client.Retrieve(storeResponse3.ObjectId)
	failOnError("Could not retrieve object", err, t)

	// Retrieve first object
	retrieveResponse, err := client.Retrieve(oid)
	failOnError("Could not retrieve old object", err, t)

	if !bytes.Equal(retrieveResponse.Plaintext, plaintext) {
		t.Fatalf("Expected plaintext %v but got %v", plaintext, retrieveResponse.Plaintext)
	}

	if !bytes.Equal(retrieveResponse.AssociatedData, associatedData) {
		t.Fatalf("Expected associated data %v but got %v", associatedData, retrieveResponse.AssociatedData)
	}
}

// Test that a user can store and retrieve a bigger object
func TestStoreRetrieveBigObject(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	object, err := crypt.Random(1024 * 1024 * 2) // 2 MB object
	failOnError("Could not create random object", err, t)
	associatedData, err := crypt.Random(1024 * 1024 * 1) // 1 MB AD
	failOnError("Could not create random object", err, t)

	storeResponse, err := client.Store(object, associatedData)
	failOnError("Store operation failed", err, t)
	oid := storeResponse.ObjectId
	_, err = client.Retrieve(oid)
	failOnError("Retrieve operation failed", err, t)
}

// Tests random sizes to store and retrieve
func TestStoreRetrieveRandomSizes(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	storeRetrieve := func(obsz uint32, adsz uint32) bool {
		// if the modulo is changed here, it also has to be changed in the error reporting below
		object, err := crypt.Random(int(obsz % 4096)) // at most 4kB object
		if err != nil {
			return false
		}

		associatedData, err := crypt.Random(int(adsz % 4096)) // at most 4kB AD
		if err != nil {
			return false
		}

		storeResponse, err := client.Store(object, associatedData)
		if err != nil {
			return false
		}

		oid := storeResponse.ObjectId
		_, err = client.Retrieve(oid)

		return err == nil
	}

	if err := quick.Check(storeRetrieve, nil); err != nil {
		if ce, ok := err.(*quick.CheckError); ok {
			obsz, ok := ce.In[0].(uint32)
			if !ok {
				t.Errorf("unable to retrieve obsz for failed test case")
			}
			adsz, ok := ce.In[1].(uint32)
			if !ok {
				t.Errorf("unable to retrieve adsz for failed test case")
			}
			// if the modulo is changed above, also change it here
			t.Errorf("Store - Retrieve for plaintext of size %d and associated data of size %d failed", obsz%4096, adsz%4096)
		}
	}
}

// Used to handle errors in go routines
// Stores a list of all errors observed
type SyncErr struct {
	mu  sync.Mutex
	err []error
}

// Atomic append to SyncErr's error list
func (e *SyncErr) append(err error) {
	e.mu.Lock()
	e.err = append(e.err, err)
	e.mu.Unlock()
}

func TestConcurrentStoreRetrieve(t *testing.T) {
	// init wait group
	var wg sync.WaitGroup

	// init SyncErr
	globErr := &SyncErr{err: []error{}}

	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func(wg *sync.WaitGroup) {
			defer wg.Done()
			plaintext, err := crypt.Random(1024) // 1KB
			if err != nil {                      // Bail out early on error
				globErr.append(fmt.Errorf("Couldn't create object: %v", err))
				return
			}
			associatedData, err := crypt.Random(1024) // 1KB
			if err != nil {                           // Bail out early on error
				globErr.append(fmt.Errorf("Couldn't create AD: %v", err))
				return
			}
			client, err := NewClient(endpoint, https)
			defer closeClient(client, t)
			if err != nil { // Bail out early on error
				globErr.append(fmt.Errorf("Couldn't create client: %v", err))
				return
			}

			_, err = client.LoginUser(uid, pwd)
			if err != nil { // Bail out early on error
				globErr.append(fmt.Errorf("Couldn't log in user: %v", err))
				return
			}

			storeResponse, err := client.Store(plaintext, associatedData)
			if err != nil { // Bail out early on error
				globErr.append(fmt.Errorf("Couldn't create store object: %v", err))
				return
			}
			oid := storeResponse.ObjectId
			retrieveResponse, err := client.Retrieve(oid)
			if err != nil { // Bail out early on error
				globErr.append(fmt.Errorf("Couldn't retrieve object: %v", err))
				return
			}
			if !bytes.Equal(retrieveResponse.Plaintext, plaintext) {
				globErr.append(fmt.Errorf("Plaintext didn't match. Expected:\n%v\n But got:\n%v", retrieveResponse.Plaintext, plaintext))
				return
			}
		}(&wg)
	}
	wg.Wait() // Wait for all go routines to be finished
	// If SyncErr contains errors, test fails and errors are returned
	if len(globErr.err) != 0 {
		t.Fatalf("Concurrent store/retrieve failed with errors: %v", globErr.err)
	}
}

// Test storage and retrieval of objects with no data and no associated data
func TestStoreRetrieveEmptyObjects(t *testing.T) {
	client, err := NewClient(endpoint, https)
	failOnError("Could not create client", err, t)
	defer closeClient(client, t)

	_, err = client.LoginUser(uid, pwd)
	failOnError("Could not log in user", err, t)

	emptyPlaintext := []byte("")
	emptyAssociatedData := []byte("")
	nonEmptyPlaintext := []byte("IM NOT EMPTY")
	nonEmptyAssociatedData := []byte("IM NOT EMPTY EITHER")

	// Store empty object and associated data
	storeResponse, err := client.Store(emptyPlaintext, emptyAssociatedData)
	failOnError("Stroing of empty object and associated data failed", err, t)
	oid := storeResponse.ObjectId
	retrieveResponse, err := client.Retrieve(oid)
	failOnError("Retrieve empty object failed", err, t)

	if !bytes.Equal(retrieveResponse.Plaintext, emptyPlaintext) {
		t.Fatalf("Expected plaintext %v but got %v", emptyPlaintext, retrieveResponse.Plaintext)
	}

	if !bytes.Equal(retrieveResponse.AssociatedData, emptyAssociatedData) {
		t.Fatalf("Expected associated data %v but got %v", emptyAssociatedData, retrieveResponse.AssociatedData)
	}

	// Store non-empty object and empty associated data
	storeResponse, err = client.Store(nonEmptyPlaintext, emptyAssociatedData)
	failOnError("Stroing of non-empty object and empty associated data failed", err, t)
	oid = storeResponse.ObjectId
	retrieveResponse, err = client.Retrieve(oid)
	failOnError("Retrieve object failed", err, t)

	if !bytes.Equal(retrieveResponse.Plaintext, nonEmptyPlaintext) {
		t.Fatalf("Expected plaintext %v but got %v", nonEmptyPlaintext, retrieveResponse.Plaintext)
	}

	if !bytes.Equal(retrieveResponse.AssociatedData, emptyAssociatedData) {
		t.Fatalf("Expected associated data %v but got %v", emptyAssociatedData, retrieveResponse.AssociatedData)
	}

	// Store empty object and non-empty associated data
	storeResponse, err = client.Store(emptyPlaintext, nonEmptyAssociatedData)
	failOnError("Stroing of empty object and associated data failed", err, t)
	oid = storeResponse.ObjectId
	retrieveResponse, err = client.Retrieve(oid)
	failOnError("Retrieve empty object failed", err, t)

	if !bytes.Equal(retrieveResponse.Plaintext, emptyPlaintext) {
		t.Fatalf("Expected plaintext %v but got %v", emptyPlaintext, retrieveResponse.Plaintext)
	}

	if !bytes.Equal(retrieveResponse.AssociatedData, nonEmptyAssociatedData) {
		t.Fatalf("Expected associated data %v but got %v", nonEmptyAssociatedData, retrieveResponse.AssociatedData)
	}
}
