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

var enc = Enc{
	Authorizer:  authorizer,
	DataCryptor: cryptor,
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

func TestEncryptDecrypt(t *testing.T) {
	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

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
}

func TestDecryptFail(t *testing.T) {
	ctx := setCtxKeys()

	fakeRequest := &DecryptRequest{
		Ciphertext:     []byte("fakecipher"),
		AssociatedData: []byte("fakeaad"),
		ObjectId:       "fakeobjectID",
	}

	_, err := enc.Decrypt(ctx, fakeRequest)
	if err == nil {
		t.Fatalf("Decrypt should have errored")
	}
}

func TestDecryptWrongAAD(t *testing.T) {
	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

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
}

func TestDecryptWrongOID(t *testing.T) {
	ctx := setCtxKeys()

	plaintext := []byte("plaintext_bytes")
	associatedData := []byte("associated_data_bytes")

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
}
