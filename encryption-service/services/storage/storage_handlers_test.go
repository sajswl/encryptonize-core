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
package storage

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/impl/authstorage"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
	"encryption-service/impl/objectstorage"
	"encryption-service/interfaces"
)

var cryptor, _ = crypt.NewAESCryptor([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
var authorizer = &authzimpl.Authorizer{
	AccessObjectCryptor: cryptor,
}

var objectStore = make(map[string][]byte)

var objectStoreMock = &objectstorage.ObjectStoreMock{
	StoreFunc: func(ctx context.Context, objectID string, object []byte) error {
		objectStore[objectID] = object
		return nil
	},
	RetrieveFunc: func(ctx context.Context, objectID string) ([]byte, error) {
		object, exists := objectStore[objectID]
		if !exists {
			return nil, interfaces.ErrNotFound
		}
		return object, nil
	},
	DeleteFunc: func(ctx context.Context, objectID string) error {
		delete(objectStore, objectID)
		return nil
	},
}

var strg = Storage{
	Authorizer:  authorizer,
	DataCryptor: cryptor,
	ObjectStore: objectStoreMock,
}

var userID = uuid.Must(uuid.NewV4())
var woek, _ = crypt.Random(32)
var accessObject = &common.AccessObject{Woek: woek}

var accessObjectStore = make(map[uuid.UUID]common.ProtectedAccessObject)

var authStorageTxMock = &authstorage.AuthStoreTxMock{
	InsertAcccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
		accessObjectStore[protected.ObjectID] = protected
		return nil
	},
	GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
		protected, exists := accessObjectStore[objectID]
		if !exists {
			return nil, interfaces.ErrNotFound
		}
		return &protected, nil
	},
	DeleteAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) error {
		delete(accessObjectStore, objectID)
		return nil
	},
	CommitFunc: func(ctx context.Context) error {
		return nil
	},
}

func setCtxKeys() context.Context {
	ctx := context.WithValue(context.Background(), common.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStorageTxMock)
	return ctx
}

// Test normal store and retrieve flow
func TestStoreRetrieve(t *testing.T) {
	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	storeResponse, err := strg.Store(
		ctx,
		&StoreRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)

	if err != nil {
		t.Fatalf("Storing object failed: %v", err)
	}

	// Add access object to context
	accessObject, err := strg.Authorizer.FetchAccessObject(ctx, uuid.FromStringOrNil(storeResponse.ObjectId))
	if err != nil {
		t.Fatalf("Failed to fetch access object: %s", err)
	}

	ctx = context.WithValue(ctx, common.AccessObjectCtxKey, accessObject)

	retrieveResponse, err := strg.Retrieve(
		ctx,
		&RetrieveRequest{
			ObjectId: storeResponse.ObjectId,
		},
	)

	if err != nil {
		t.Fatalf("Retrieving object failed: %v", err)
	}

	if !reflect.DeepEqual(plaintext, retrieveResponse.Plaintext) {
		t.Fatalf("Retrieved plaintext not equal to stored plaintext: %v != %v", retrieveResponse.Plaintext, plaintext)
	}

	if !reflect.DeepEqual(associatedData, retrieveResponse.AssociatedData) {
		t.Fatalf("Retrieved associatedData not equal to stored associatedData: %v != %v", retrieveResponse.AssociatedData, associatedData)
	}
}

// Test that retrieving a non-existing object fails
func TestRetrieveBeforeStore(t *testing.T) {
	ctx := setCtxKeys()

	retrieveResponse, err := strg.Retrieve(
		ctx,
		&RetrieveRequest{
			ObjectId: uuid.Must(uuid.NewV4()).String(),
		},
	)
	if retrieveResponse != nil {
		t.Fatalf("Expected nil retrieveResponse, got: %v", retrieveResponse)
	}
	if err == nil {
		t.Fatalf("Retrieve before store did not fail as expected")
	}
}

// Test the case where the object store fails to store
func TestStoreFail(t *testing.T) {
	objectStore := &objectstorage.ObjectStoreMock{
		StoreFunc: func(ctx context.Context, objectID string, object []byte) error { return fmt.Errorf("") },
	}

	strg := Storage{
		Authorizer:  authorizer,
		DataCryptor: cryptor,
		ObjectStore: objectStore,
	}

	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	storeResponse, err := strg.Store(
		ctx,
		&StoreRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)
	if storeResponse != nil {
		t.Fatalf("Expected nil storeResponse, got: %v", storeResponse)
	}
	if err == nil {
		t.Fatalf("Store did not fail as expected")
	}
}

// Test the case where the authn store fails to store
func TestStoreFailAuth(t *testing.T) {
	ctx := setCtxKeys()

	authStorageTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			return fmt.Errorf("")
		},
	}

	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStorageTx)

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	storeResponse, err := strg.Store(
		ctx,
		&StoreRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)
	if storeResponse != nil {
		t.Fatalf("Expected nil storeResponse, got: %v", storeResponse)
	}
	if err == nil {
		t.Fatalf("Store did not fail as expected")
	}
}

// Tests that deleting an object works
func TestRetrieveAfterDelete(t *testing.T) {
	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	storeResponse, err := strg.Store(
		ctx,
		&StoreRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)

	if err != nil {
		t.Fatalf("Storing object failed: %v", err)
	}

	_, err = strg.Delete(
		ctx,
		&DeleteRequest{
			ObjectId: storeResponse.ObjectId,
		},
	)

	if err != nil {
		t.Fatalf("Deleting object failed: %v", err)
	}

	retrieveResponse, err := strg.Retrieve(
		ctx,
		&RetrieveRequest{
			ObjectId: storeResponse.ObjectId,
		},
	)

	if retrieveResponse != nil {
		t.Fatalf("Expected nil retrieveResponse, got: %v", retrieveResponse)
	}

	if err == nil {
		t.Fatalf("Retrieve after delete did not fail as expected")
	}
}

func TestUpdateObject(t *testing.T) {
	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	storeResponse, err := strg.Store(
		ctx,
		&StoreRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)

	if err != nil {
		t.Fatalf("Storing object failed: %v", err)
	}

	// Add access object to context
	accessObject, err := strg.Authorizer.FetchAccessObject(ctx, uuid.FromStringOrNil(storeResponse.ObjectId))
	if err != nil {
		t.Fatalf("Failed to fetch access object: %s", err)
	}

	ctx = context.WithValue(ctx, common.AccessObjectCtxKey, accessObject)

	updatedPlaintext := []byte("updated_plaintext_bytes")
	updatedAssociatedData := []byte("updated_associated_data_bytes")

	_, err = strg.Update(
		ctx,
		&UpdateRequest{
			ObjectId:       storeResponse.ObjectId,
			Plaintext:      updatedPlaintext,
			AssociatedData: updatedAssociatedData,
		},
	)

	if err != nil {
		t.Fatalf("Updating object failed: %v", err)
	}

	retrieveResponse, err := strg.Retrieve(
		ctx,
		&RetrieveRequest{
			ObjectId: storeResponse.ObjectId,
		},
	)

	if err != nil {
		t.Fatalf("Retrieving object failed: %v", err)
	}

	if !reflect.DeepEqual(updatedPlaintext, retrieveResponse.Plaintext) {
		t.Fatalf("Retrieved plaintext not equal to updated plaintext: %v != %v", retrieveResponse.Plaintext, updatedPlaintext)
	}

	if !reflect.DeepEqual(updatedAssociatedData, retrieveResponse.AssociatedData) {
		t.Fatalf("Retrieved associatedData not equal to updated associatedData: %v != %v", retrieveResponse.AssociatedData, updatedAssociatedData)
	}
}
