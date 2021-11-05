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
package authz

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/impl/authstorage"
	"encryption-service/impl/crypt"
)

var objectID = uuid.Must(uuid.FromString("20000000-0000-0000-0000-000000000000"))
var userID = uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000"))
var woek = []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
var accessObject = &common.AccessObject{
	Version: 0,
	UserIDs: map[uuid.UUID]bool{
		userID: true,
	},
	Woek: woek,
}

var cryptor, _ = crypt.NewAESCryptor([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
var authorizer = &Authorizer{
	AccessObjectCryptor: cryptor,
}

func TestRemoveUserNonExisting(t *testing.T) {
	expected := accessObject.UserIDs

	accessObject.RemoveUser(uuid.Must(uuid.FromString("A0000000-0000-0000-0000-000000000000")))

	if !reflect.DeepEqual(expected, accessObject.UserIDs) {
		t.Error("Remove User Non Existing failed")
	}
}

func TestCreateObject(t *testing.T) {
	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			ao := &common.AccessObject{}
			err := cryptor.DecodeAndDecrypt(ao, protected.WrappedKey, protected.AccessObject, objectID.Bytes())
			if err != nil {
				t.Fatalf("Failed to decrypt access object: %s", err)
			}
			if !reflect.DeepEqual(accessObject, ao) {
				t.Fatalf("Decrypted access object is different from original")
			}

			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	err := authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err != nil {
		t.Fatalf("CreateAccessObject errored: %s", err)
	}
}

func TestCreateObjectFail(t *testing.T) {
	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			return errors.New("mock error")
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	err := authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err == nil || err.Error() != "mock error" {
		t.Error("CreateObject should have errored")
	}
}

func TestFetchAccessObject(t *testing.T) {
	wrappedKey, ciphertext, err := cryptor.EncodeAndEncrypt(accessObject, objectID.Bytes())
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}
	protected := common.ProtectedAccessObject{
		ObjectID:     objectID,
		AccessObject: ciphertext,
		WrappedKey:   wrappedKey,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) (*common.ProtectedAccessObject, error) {
			return &protected, nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	_, err = authorizer.FetchAccessObject(ctx, objectID)
	if err != nil {
		t.Fatalf("FetchAccessObject errored: %v", err)
	}
}

func TestAuthorizeStoreFailed(t *testing.T) {
	authStoreTx := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) (*common.ProtectedAccessObject, error) {
			return nil, errors.New("mock error")
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	_, err := authorizer.FetchAccessObject(ctx, objectID)
	if err == nil {
		t.Fatal("Authorize should have errored")
	}
}

func TestAuthorizeDecryptFailed(t *testing.T) {
	wrappedKey, ciphertext, err := cryptor.EncodeAndEncrypt(accessObject, objectID.Bytes())
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}
	protected := common.ProtectedAccessObject{
		ObjectID:     objectID,
		AccessObject: ciphertext[1:], // Mangled ciphertext
		WrappedKey:   wrappedKey,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) (*common.ProtectedAccessObject, error) {
			return &protected, nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	_, err = authorizer.FetchAccessObject(ctx, objectID)
	if err == nil {
		t.Fatal("Authorize should have errored")
	}
}

func TestUpdate(t *testing.T) {
	objectID := uuid.Must(uuid.NewV4())
	newAccessObject := &common.AccessObject{
		Version: 42,
		UserIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.FromString("30000000-0000-0000-0000-000000000000")): true,
		},
		Woek: []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"),
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		UpdateAccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			ao := &common.AccessObject{}
			err := cryptor.DecodeAndDecrypt(ao, protected.WrappedKey, protected.AccessObject, objectID.Bytes())
			if err != nil {
				t.Fatalf("Failed to decrypt access object: %s", err)
			}
			newAccessObject.Version++
			if !reflect.DeepEqual(newAccessObject, ao) {
				t.Fatalf("Decrypted access object is different from original")
			}

			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	err := authorizer.UpdateAccessObject(ctx, objectID, *newAccessObject)
	if err != nil {
		t.Fatalf("updatePermissions errored: %v", err)
	}
}

func TestUpdateStoreFailed(t *testing.T) {
	authStoreTx := &authstorage.AuthStoreTxMock{
		UpdateAccessObjectFunc: func(ctx context.Context, protected common.ProtectedAccessObject) error {
			return errors.New("mock error")
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	err := authorizer.UpdateAccessObject(ctx, objectID, *accessObject)
	if err == nil {
		t.Fatalf("updatePermissions should have errored")
	}
}
