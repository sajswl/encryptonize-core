// Copyright 2020 CYBERCRYPT
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

	"encryption-service/authstorage"
	"encryption-service/crypt"
)

// TODO: accessObject comes from access_object_test.go this is not nice

var messageAuthenticator, _ = crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
var authorizer = &Authorizer{
	MessageAuthenticator: messageAuthenticator,
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

	// DeepEqual doesn't work here
	if accessObject.String() != parsedAccessObject.String() {
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
	tag, err := authorizer.MessageAuthenticator.Tag(crypt.UsersDomain, append(userID.Bytes(), data...))
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
	kek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	insertCalledCorrectly := false

	authorizer.Store = &authstorage.AuthStoreMock{
		InsertAcccessObjectFunc: func(ctx context.Context, oid uuid.UUID, data, tag []byte) error {
			accessObject, err := authorizer.ParseAccessObject(oid, data, tag)
			if err != nil {
				t.Errorf("parseAccessObject errored: %v", err)
			}
			insertCalledCorrectly = (oid == objectID) && accessObject.ContainsUser(userID)
			return nil
		},
	}

	_, err = authorizer.CreateObject(context.Background(), objectID, userID, kek)
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

	authorizer.Store = &authstorage.AuthStoreMock{
		InsertAcccessObjectFunc: func(ctx context.Context, oid uuid.UUID, data, tag []byte) error {
			return errors.New("mock error")
		},
	}

	oek, err := authorizer.CreateObject(context.Background(), objectID, userID, woek)
	if oek != nil || err == nil || err.Error() != "mock error" {
		t.Error("CreateObject should have errored")
	}
}

func TestAuthorize(t *testing.T) {
	userID := uuid.Must(uuid.FromString("10000000-0000-0000-0000-000000000000"))

	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}

	authorizer.Store = &authstorage.AuthStoreMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return data, tag, nil
		},
	}

	_, authorized, err := authorizer.Authorize(context.Background(), objectID, userID)
	if err != nil {
		t.Fatalf("Authorize errored: %v", err)
	}

	if !authorized {
		t.Error("authorized was not ok")
	}
}

func TestAuthorizeStoreFailed(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())

	authorizer.Store = &authstorage.AuthStoreMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return nil, nil, errors.New("mock error")
		},
	}

	_, _, err := authorizer.Authorize(context.Background(), objectID, userID)
	if err == nil {
		t.Fatal("Authorize should have errored")
	}
}

func TestAuthorizeParseFailed(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())

	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}

	authorizer.Store = &authstorage.AuthStoreMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return data, append(tag, []byte("bad")...), nil
		},
	}

	_, _, err = authorizer.Authorize(context.Background(), objectID, userID)
	if err == nil {
		t.Fatal("Authorize should have errored")
	}
}

func TestAuthorizeWrongUserID(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())

	data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
	if err != nil {
		t.Fatalf("serializeAccessObject errored: %v", err)
	}

	authorizer.Store = &authstorage.AuthStoreMock{
		GetAccessObjectFunc: func(ctx context.Context, oid uuid.UUID) ([]byte, []byte, error) {
			return data, tag, nil
		},
	}

	accessObject, authorized, err := authorizer.Authorize(context.Background(), objectID, userID)
	if err != nil {
		t.Fatalf("Authorize errored: %v", err)
	}

	if accessObject != nil || authorized {
		t.Error("authorized was ok")
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

	authorizer.Store = &authstorage.AuthStoreMock{
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			gotData = data
			gotTag = tag
			return nil
		},
	}
	err := authorizer.updatePermissions(context.Background(), objectID, accessObject)
	if err != nil {
		t.Fatalf("updatePermissions errored: %v", err)
	}

	gotAccessObject, err := authorizer.ParseAccessObject(objectID, gotData, gotTag)
	if err != nil {
		t.Fatalf("parseAccessObject errored: %v", err)
	}

	if accessObject.String() != gotAccessObject.String() || gotAccessObject.Version != 5 {
		t.Error("access objects didn't match")
	}
}

func TestUpdatePermissionsStoreFailed(t *testing.T) {
	authorizer.Store = &authstorage.AuthStoreMock{
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return errors.New("mock error")
		},
	}
	err := authorizer.updatePermissions(context.Background(), objectID, accessObject)
	if err == nil {
		t.Fatalf("updatePermissions should have errored")
	}
}

func TestAddPermission(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &AccessObject{
		Version: 4,
		UserIds: [][]byte{uuid.Must(uuid.NewV4()).Bytes()},
		Woek:    []byte("woek"),
	}

	var gotData, gotTag []byte

	authorizer.Store = &authstorage.AuthStoreMock{
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			gotData = data
			gotTag = tag
			return nil
		},
	}
	err := authorizer.AddPermission(context.Background(), accessObject, objectID, userID)
	if err != nil {
		t.Fatalf("updatePermissions errored: %v", err)
	}

	gotAccessObject, err := authorizer.ParseAccessObject(objectID, gotData, gotTag)
	if err != nil {
		t.Fatalf("parseAccessObject errored: %v", err)
	}
	if accessObject.String() != gotAccessObject.String() || gotAccessObject.Version != 5 {
		t.Error("access objects didn't match")
	}

	if !accessObject.ContainsUser(userID) {
		t.Error("access object didn't container userID")
	}
}

func TestRemovePermission(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &AccessObject{
		Version: 4,
		UserIds: [][]byte{uuid.Must(uuid.NewV4()).Bytes()},
		Woek:    []byte("woek"),
	}

	var gotData, gotTag []byte

	authorizer.Store = &authstorage.AuthStoreMock{
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			gotData = data
			gotTag = tag
			return nil
		},
	}
	err := authorizer.RemovePermission(context.Background(), accessObject, objectID, userID)
	if err != nil {
		t.Fatalf("updatePermissions errored: %v", err)
	}

	gotAccessObject, err := authorizer.ParseAccessObject(objectID, gotData, gotTag)
	if err != nil {
		t.Fatalf("parseAccessObject errored: %v", err)
	}
	if accessObject.String() != gotAccessObject.String() || gotAccessObject.Version != 5 {
		t.Error("access objects didn't match")
	}

	if accessObject.ContainsUser(userID) {
		t.Error("access object did container userID")
	}
}
