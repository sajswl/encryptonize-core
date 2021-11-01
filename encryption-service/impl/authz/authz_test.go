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

	"encryption-service/contextkeys"
	"encryption-service/impl/authstorage"
	"encryption-service/impl/crypt"
)

// TODO: accessObject comes from access_object_test.go this is not nice

var messageAuthenticator, _ = crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), crypt.TokenDomain)
var authorizer = &Authorizer{
	AccessObjectMAC: messageAuthenticator,
}

func TestRemoveUserNonExisting(t *testing.T) {
	expected := append([][]byte(nil), accessObject.UserIds...)

	accessObject.RemoveUser(uuid.Must(uuid.FromString("A0000000-0000-0000-0000-000000000000")))

	if !reflect.DeepEqual(expected, accessObject.UserIds) {
		t.Error("Remove User Non Existing failed")
	}
}

func TestSerializeParse(t *testing.T) {
	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject failed: %v", err)
	}

	parsedAccessObject, err := authorizer.ParseAccessObject(objectID, data, tag)
	if err != nil {
		t.Fatalf("parseAccessObject failed: %v", err)
	}

	if !reflect.DeepEqual(accessObject, parsedAccessObject) {
		t.Error("TestSerializeParse failed")
	}
}

func TestParseBadObjectID(t *testing.T) {
	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject failed: %v", err)
	}

	parsedAccessObject, err := authorizer.ParseAccessObject(uuid.Must(uuid.NewV4()), data, tag)
	if parsedAccessObject != nil || err == nil || err.Error() != "invalid tag" {
		t.Error("TestParseBadObjectID failed")
	}
}

func TestParseBadSignedData(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	data := []byte("parsers hate this string")
	tag, err := authorizer.AccessObjectMAC.Tag(append(userID.Bytes(), data...))
	if err != nil {
		t.Fatalf("tag failed: %v", err)
	}

	parsedAccessObject, err := authorizer.ParseAccessObject(userID, data, tag)
	if parsedAccessObject != nil || err == nil {
		t.Error("TestParseBadSignedData failed")
	}
}

func TestParseBadTag(t *testing.T) {
	parsedAccessObject, err := authorizer.ParseAccessObject(uuid.Must(uuid.NewV4()), []byte("data"), []byte("tag"))
	if parsedAccessObject != nil || err == nil {
		t.Error("TestParseBadTagfailed")
	}
}

func TestCreateObject(t *testing.T) {
	objectID := uuid.Must(uuid.NewV4())
	userID := uuid.Must(uuid.NewV4())
	woek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	insertCalledCorrectly := false

	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, oid uuid.UUID, data, tag []byte) error {
			accessObject, err := authorizer.ParseAccessObject(oid, data, tag)
			if err != nil {
				t.Errorf("parseAccessObject errored: %v", err)
			}
			insertCalledCorrectly = (oid == objectID) && accessObject.ContainsUser(userID)
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	err = authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err != nil {
		t.Error("CreateObject errored")
	}

	if !insertCalledCorrectly {
		t.Error("insert not called correctly")
	}
}

func TestCreateObjectFail(t *testing.T) {
	objectID := uuid.Must(uuid.NewV4())
	userID := uuid.Must(uuid.NewV4())
	woek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertAcccessObjectFunc: func(ctx context.Context, oid uuid.UUID, data, tag []byte) error {
			return errors.New("mock error")
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	err = authorizer.CreateAccessObject(ctx, objectID, userID, woek)
	if err == nil || err.Error() != "mock error" {
		t.Error("CreateObject should have errored")
	}
}

func TestFetchAccessObject(t *testing.T) {
	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return data, tag, nil
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	_, err = authorizer.FetchAccessObject(ctx, objectID)
	if err != nil {
		t.Fatalf("FetchAccessObject errored: %v", err)
	}
}

func TestAuthorizeStoreFailed(t *testing.T) {
	authStoreTx := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return nil, nil, errors.New("mock error")
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	_, err := authorizer.FetchAccessObject(ctx, objectID)
	if err == nil {
		t.Fatal("Authorize should have errored")
	}
}

func TestAuthorizeParseFailed(t *testing.T) {
	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return data, append(tag, []byte("bad")...), nil
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	_, err = authorizer.FetchAccessObject(ctx, objectID)
	if err == nil {
		t.Fatal("Authorize should have errored")
	}
}

func TestUpdatePermissions(t *testing.T) {
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &AccessObject{
		Version: 4,
		UserIds: [][]byte{uuid.Must(uuid.NewV4()).Bytes()},
		Woek:    []byte("woek"),
	}

	var gotData, gotTag []byte

	authStoreTx := &authstorage.AuthStoreTxMock{
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			gotData = data
			gotTag = tag
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	err := authorizer.UpsertAccessObject(ctx, objectID, accessObject)
	if err != nil {
		t.Fatalf("updatePermissions errored: %v", err)
	}

	gotAccessObject, err := authorizer.ParseAccessObject(objectID, gotData, gotTag)
	if err != nil {
		t.Fatalf("parseAccessObject errored: %v", err)
	}

	if !reflect.DeepEqual(accessObject, gotAccessObject) || gotAccessObject.Version != 5 {
		t.Error("access objects didn't match")
	}
}

func TestUpdatePermissionsStoreFailed(t *testing.T) {
	authStoreTx := &authstorage.AuthStoreTxMock{
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return errors.New("mock error")
		},
	}
	ctx := context.WithValue(context.Background(), contextkeys.AuthStorageTxCtxKey, authStoreTx)

	err := authorizer.UpsertAccessObject(ctx, objectID, accessObject)
	if err == nil {
		t.Fatalf("updatePermissions should have errored")
	}
}
