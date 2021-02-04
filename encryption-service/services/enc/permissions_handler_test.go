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
package enc

import (
	"context"
	"reflect"
	"testing"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/impl/authstorage"
	"encryption-service/impl/authz"
	"encryption-service/impl/crypt"
)

var ma, _ = crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), crypt.AccessObjectsDomain)
var authorizer = &authz.Authorizer{
	AccessObjectMAC: ma,
}

var enc = Enc{
	AccessObjectMAC: ma,
}

var targetID = uuid.Must(uuid.NewV4())
var userID = uuid.Must(uuid.NewV4())
var objectID = uuid.Must(uuid.NewV4())
var Woek, err = crypt.Random(32)

var accessObject = &authz.AccessObject{
	UserIds: [][]byte{
		userID.Bytes(),
	},
	Woek:    Woek,
	Version: 0,
}

// Create accessObject without userID
var unAuthAccessObject = &authz.AccessObject{
	UserIds: [][]byte{
		uuid.Must(uuid.NewV4()).Bytes(),
	},
	Woek:    Woek,
	Version: 0,
}

var authnStorageTxMock = &authstorage.AuthStoreTxMock{
	GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
		data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
		return data, tag, err
	},
	UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
		return nil
	},
	CommitFunc: func(ctx context.Context) error {
		return nil
	},
	UserExistsFunc: func(ctx context.Context, userID uuid.UUID) (bool, error) {
		return true, nil
	},
}

func TestGetPermissions(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)
	expected := []string{userID.String()}

	getPermissionsResponse, err := enc.GetPermissions(ctx, &GetPermissionsRequest{ObjectId: objectID.String()})
	if err != nil {
		t.Fatalf("Couldn't get user: %v", err)
	}

	if !reflect.DeepEqual(expected, getPermissionsResponse.UserIds) {
		t.Fatal("Wrong users returned")
	}
}

func TestGetPermissionsMissingOID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.GetPermissions(ctx, &GetPermissionsRequest{})
	if err == nil {
		t.Fatalf("No object id given, should have failed")
	}
}

func TestGetPermissionUnauthorized(t *testing.T) {
	authnStorageTxMock := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
			data, tag, err := authorizer.SerializeAccessObject(objectID, unAuthAccessObject)
			return data, tag, err
		},
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return nil
		},
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.GetPermissions(ctx, &GetPermissionsRequest{ObjectId: objectID.String()})
	if err == nil {
		t.Fatalf("User should not be authorized")
	}
	if errStatus, _ := status.FromError(err); codes.PermissionDenied != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.PermissionDenied, errStatus)
	}
}

func TestAddPermission(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})
	if err != nil {
		t.Fatalf("Couldn't add user: %v", err)
	}
}

// Tests that a permission cannot be added if the target user doesn't exist
func TestAddPermissionNoTargetUser(t *testing.T) {
	// Temporarily overwrite UserExistsFunc to return error
	oldUserExists := authnStorageTxMock.UserExistsFunc
	authnStorageTxMock.UserExistsFunc = func(ctx context.Context, userID uuid.UUID) (bool, error) {
		return false, nil
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})

	// Restore the original GetTag function for the other tests
	authnStorageTxMock.UserExistsFunc = oldUserExists

	if err == nil {
		t.Fatalf("Shouldn't able to add user that does not exist!")
	}
}

func TestAddPermissionUnauthorized(t *testing.T) {
	authnStorageTxMock := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
			data, tag, err := authorizer.SerializeAccessObject(objectID, unAuthAccessObject)
			return data, tag, err
		},
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return nil
		},
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})
	if err == nil {
		t.Fatalf("User should not be authorized")
	}
	if errStatus, _ := status.FromError(err); codes.PermissionDenied != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.PermissionDenied, errStatus)
	}
}

func TestAddPermissionMissingOID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.AddPermission(ctx, &AddPermissionRequest{Target: targetID.String()})
	if err == nil {
		t.Fatalf("No object id given, should have failed")
	}
}

func TestAddPermissionMissingTarget(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String()})
	if err == nil {
		t.Fatalf("No target id given, should have failed")
	}
}

func TestRemovePermission(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.RemovePermission(ctx, &RemovePermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})
	if err != nil {
		t.Fatalf("Couldn't remove user: %v", err)
	}
}

func TestRemovePermissionUnauthorized(t *testing.T) {
	authnStorageTxMock := &authstorage.AuthStoreTxMock{
		GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
			data, tag, err := authorizer.SerializeAccessObject(objectID, unAuthAccessObject)
			return data, tag, err
		},
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return nil
		},
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.RemovePermission(ctx, &RemovePermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})
	if err == nil {
		t.Fatalf("User should not be authorized")
	}
	if errStatus, _ := status.FromError(err); codes.PermissionDenied != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.PermissionDenied, errStatus)
	}
}

func TestRemovePermissionMissingTarget(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.RemovePermission(ctx, &RemovePermissionRequest{ObjectId: objectID.String()})
	if err == nil {
		t.Fatalf("No target id given, should have failed")
	}
}

func TestRemovePermissionMissingOID(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = enc.RemovePermission(ctx, &RemovePermissionRequest{Target: targetID.String()})
	if err == nil {
		t.Fatalf("No object id given, should have failed")
	}
}
