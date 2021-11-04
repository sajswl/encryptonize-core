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
	"encryption-service/contextkeys"
	"encryption-service/impl/authstorage"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
	"encryption-service/impl/objectstorage"
)

type ObjectStoreMock struct {
	StoreFunc    func(ctx context.Context, objectID string, object []byte) error
	RetrieveFunc func(ctx context.Context, objectID string) ([]byte, error)
	DeleteFunc   func(ctx context.Context, objectID string) error
}

func (o *ObjectStoreMock) Store(ctx context.Context, objectID string, object []byte) error {
	return o.StoreFunc(ctx, objectID, object)
}

func (o *ObjectStoreMock) Retrieve(ctx context.Context, objectID string) ([]byte, error) {
	return o.RetrieveFunc(ctx, objectID)
}

func (o *ObjectStoreMock) Delete(ctx context.Context, objectID string) error {
	return o.DeleteFunc(ctx, objectID)
}

var cryptor, _ = crypt.NewAESCryptor([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
var authorizer = &authzimpl.Authorizer{
	AccessObjectCryptor: cryptor,
}

// Test normal store and retrieve flow
func TestStoreRetrieve(t *testing.T) {
	authStore := authstorage.NewMemoryAuthStore()
	authStorageTx, _ := authStore.NewTransaction(context.TODO())

	dataCryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	strg := Storage{
		ObjectStore: objectstorage.NewMemoryObjectStore(),
		Authorizer:  authorizer,
		DataCryptor: dataCryptor,
	}

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStorageTx)

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

	ctx = context.WithValue(ctx, contextkeys.AccessObjectCtxKey, accessObject)

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
	authStore := authstorage.NewMemoryAuthStore()
	authStorageTx, _ := authStore.NewTransaction(context.TODO())

	dataCryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	strg := Storage{
		ObjectStore: objectstorage.NewMemoryObjectStore(),
		Authorizer:  authorizer,
		DataCryptor: dataCryptor,
	}

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStorageTx)

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
	objectStore := &ObjectStoreMock{
		StoreFunc: func(ctx context.Context, objectID string, object []byte) error { return fmt.Errorf("") },
	}
	authStorageTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			return nil
		},
	}
	dataCryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	strg := Storage{
		ObjectStore: objectStore,
		Authorizer:  authorizer,
		DataCryptor: dataCryptor,
	}

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStorageTx)

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
	authStorageTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			return fmt.Errorf("")
		},
	}
	dataCryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	strg := Storage{
		ObjectStore: objectstorage.NewMemoryObjectStore(),
		Authorizer:  authorizer,
		DataCryptor: dataCryptor,
	}

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStorageTx)

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
