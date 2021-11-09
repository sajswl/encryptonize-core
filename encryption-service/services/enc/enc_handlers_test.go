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
package enc

import (
	"bytes"
	"context"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/impl/authstorage"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
)

var cryptor, _ = crypt.NewAESCryptor([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
var authorizer = &authzimpl.Authorizer{
	AccessObjectCryptor: cryptor,
}

func initMockEnc(t *testing.T) (Enc, interfaces.AuthStoreInterface) {
	authStore, err := authstorage.NewMemoryAuthStore("./db.dat")
	if err != nil {
		t.Fatalf("Cannot create a new MemoryAuthStore: %v", err)
	}
	cryptor, err := crypt.NewAESCryptor(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewAESCryptor failed: %v", err)
	}

	enc := Enc{
		Authorizer:  authorizer,
		DataCryptor: cryptor,
	}

	return enc, authStore
}

func TestEncryptDecrypt(t *testing.T) {
	enc, authStore := initMockEnc(t)

	authStorageTx, err := authStore.NewTransaction(context.TODO())
	if err != nil {
		t.Fatalf("New transaction failed: %v", err)
	}

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), common.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStorageTx)
	encryptResponse, err := enc.Encrypt(
		ctx,
		&EncryptRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)

	if err != nil {
		t.Fatalf("Encrypting object failed: %v", err)
	}

	if !bytes.Equal(encryptResponse.AssociatedData, associatedData) {
		t.Fatalf("Associated data from encryption response is not the same!")
	}

	// Add access object to context
	accessObject, err := enc.Authorizer.FetchAccessObject(ctx, uuid.FromStringOrNil(encryptResponse.ObjectId))
	if err != nil {
		t.Fatalf("Failed to fetch access object: %s", err)
	}

	ctx = context.WithValue(ctx, common.AccessObjectCtxKey, accessObject)

	decryptResponse, err := enc.Decrypt(
		ctx,
		&DecryptRequest{
			ObjectId:       encryptResponse.ObjectId,
			Ciphertext:     encryptResponse.Ciphertext,
			AssociatedData: encryptResponse.AssociatedData,
		},
	)

	if err != nil {
		t.Fatalf("Decrypting object failed: %v", err)
	}

	if !bytes.Equal(decryptResponse.Plaintext, plaintext) {
		t.Fatalf("Decrypted plaintext does not equal original plaintext!")
	}

	if !bytes.Equal(decryptResponse.AssociatedData, associatedData) {
		t.Fatalf("Associated data from decryption response is not the same!")
	}

	authStore.Close()
}

func TestDecryptFail(t *testing.T) {
	enc, authStore := initMockEnc(t)

	fakeRequest := &DecryptRequest{
		Ciphertext:     []byte("fakecipher"),
		AssociatedData: []byte("fakeaad"),
		ObjectId:       "fakeobjectID",
	}

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), common.UserIDCtxKey, userID)

	_, err = enc.Decrypt(ctx, fakeRequest)
	if err == nil {
		t.Fatalf("Decrypt should have errored")
	}

	authStore.Close()
}

func TestDecryptWrongAAD(t *testing.T) {
	enc, authStore := initMockEnc(t)

	authStorageTx, err := authStore.NewTransaction(context.TODO())
	if err != nil {
		t.Fatalf("New transaction failed: %v", err)
	}

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), common.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStorageTx)
	encryptResponse, err := enc.Encrypt(
		ctx,
		&EncryptRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)

	if err != nil {
		t.Fatalf("Encrypting object failed: %v", err)
	}

	fakeAAD := []byte("other")

	_, err = enc.Decrypt(
		ctx,
		&DecryptRequest{
			ObjectId:       encryptResponse.ObjectId,
			Ciphertext:     encryptResponse.Ciphertext,
			AssociatedData: fakeAAD,
		},
	)

	if err == nil {
		t.Fatal("Decrypting object should've failed with wrong AAD")
	}

	authStore.Close()
}

func TestDecryptWrongOID(t *testing.T) {
	enc, authStore := initMockEnc(t)

	authStorageTx, err := authStore.NewTransaction(context.TODO())
	if err != nil {
		t.Fatalf("New transaction failed: %v", err)
	}

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

	userID, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("Could not create user ID: %v", err)
	}

	ctx := context.WithValue(context.Background(), common.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStorageTx)
	encryptResponse, err := enc.Encrypt(
		ctx,
		&EncryptRequest{
			Plaintext:      plaintext,
			AssociatedData: associatedData,
		},
	)

	if err != nil {
		t.Fatalf("Encrypting object failed: %v", err)
	}

	plaintext2 := []byte("plaintext_bytes2")
	associatedData2 := []byte("associated_data_bytes2")

	ctx = context.WithValue(context.Background(), common.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStorageTx)
	encryptResponse2, err := enc.Encrypt(
		ctx,
		&EncryptRequest{
			Plaintext:      plaintext2,
			AssociatedData: associatedData2,
		},
	)

	if err != nil {
		t.Fatalf("Encrypting object failed: %v", err)
	}

	// Object id from different object than Ciphertext and AAD
	_, err = enc.Decrypt(
		ctx,
		&DecryptRequest{
			ObjectId:       encryptResponse2.ObjectId,
			Ciphertext:     encryptResponse.Ciphertext,
			AssociatedData: encryptResponse.AssociatedData,
		},
	)

	if err == nil {
		t.Fatal("Decrypting object should've failed with wrong ObjectID")
	}

	authStore.Close()
}
