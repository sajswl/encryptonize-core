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
	"reflect"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/impl/authstorage"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
)

var cryptor, _ = crypt.NewAESCryptor([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
var authorizer = &authzimpl.Authorizer{
	AccessObjectCryptor: cryptor,
}

var permissions = Authz{
	Authorizer: authorizer,
}

var targetID = uuid.Must(uuid.NewV4())
var userID = uuid.Must(uuid.NewV4())
var objectID = uuid.Must(uuid.NewV4())
var Woek, err = crypt.Random(32)

var accessObject = &common.AccessObject{
	GroupIDs: map[uuid.UUID]bool{
		userID: true,
	},
	Woek:    Woek,
	Version: 0,
}

var authnStorageTxMock = &authstorage.AuthStoreTxMock{
	GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
		wrappedKey, ciphertext, err := cryptor.EncodeAndEncrypt(accessObject, objectID.Bytes())
		if err != nil {
			return nil, err
		}

		return &common.ProtectedAccessObject{
			ObjectID:     objectID,
			AccessObject: ciphertext,
			WrappedKey:   wrappedKey,
		}, nil
	},
	UpdateAccessObjectFunc: func(ctx context.Context, protected *common.ProtectedAccessObject) error {
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
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	expected := []string{userID.String()}

	getPermissionsResponse, err := permissions.GetPermissions(ctx, &GetPermissionsRequest{ObjectId: objectID.String()})
	if err != nil {
		t.Fatalf("Couldn't get user: %v", err)
	}

	if !reflect.DeepEqual(expected, getPermissionsResponse.GroupIds) {
		t.Fatal("Wrong users returned")
	}
}

func TestGetPermissionsMissingAccessObject(t *testing.T) {
	_, err = permissions.GetPermissions(context.Background(), &GetPermissionsRequest{})
	if err == nil {
		t.Fatalf("No access object given, should have failed")
	}
}

func TestAddPermission(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})
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

	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})

	// Restore the original GetTag function for the other tests
	authnStorageTxMock.UserExistsFunc = oldUserExists

	if err == nil {
		t.Fatalf("Shouldn't able to add user that does not exist!")
	}
}

func TestAddPermissionMissingOID(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.AddPermission(ctx, &AddPermissionRequest{Target: targetID.String()})
	if err == nil {
		t.Fatalf("No object id given, should have failed")
	}
}

func TestAddPermissionsMissingAccessObject(t *testing.T) {
	_, err = permissions.AddPermission(context.Background(), &AddPermissionRequest{Target: targetID.String()})
	if err == nil {
		t.Fatalf("No access object given, should have failed")
	}
}

func TestAddPermissionMissingTarget(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.AddPermission(ctx, &AddPermissionRequest{ObjectId: objectID.String()})
	if err == nil {
		t.Fatalf("No target id given, should have failed")
	}
}

func TestRemovePermission(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.RemovePermission(ctx, &RemovePermissionRequest{ObjectId: objectID.String(), Target: targetID.String()})
	if err != nil {
		t.Fatalf("Couldn't remove user: %v", err)
	}
}

func TestRemovePermissionMissingTarget(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.RemovePermission(ctx, &RemovePermissionRequest{ObjectId: objectID.String()})
	if err == nil {
		t.Fatalf("No target id given, should have failed")
	}
}

func TestRemovePermissionMissingOID(t *testing.T) {
	ctx := context.WithValue(context.Background(), common.AccessObjectCtxKey, accessObject)
	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authnStorageTxMock)

	_, err = permissions.RemovePermission(ctx, &RemovePermissionRequest{Target: targetID.String()})
	if err == nil {
		t.Fatalf("No object id given, should have failed")
	}
}

func TestRemovePermissionsMissingAccessObject(t *testing.T) {
	_, err = permissions.RemovePermission(context.Background(), &RemovePermissionRequest{Target: targetID.String()})
	if err == nil {
		t.Fatalf("No access object given, should have failed")
	}
}
