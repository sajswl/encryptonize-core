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
package authn

import (
	"testing"

	"context"
	"errors"
	"reflect"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/impl/authstorage"
	"encryption-service/impl/crypt"
)

var userData = &common.UserData{
	HashedPassword: []byte("HashedPassword"),
	Salt:           []byte("Salt"),
	GroupIDs: map[uuid.UUID]bool{
		uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
	},
}

func failOnError(message string, err error, t *testing.T) {
	if err != nil {
		t.Fatalf(message+": %v", err)
	}
}

func failOnSuccess(message string, err error, t *testing.T) {
	if err == nil {
		t.Fatalf("Test expected to fail: %v", message)
	}
}

func SetupUA() (*UserAuthenticator, error) {
	tek, err := crypt.Random(32)
	if err != nil {
		return nil, errors.New("Random errored")
	}

	tokenCryptor, err := crypt.NewAESCryptor(tek)
	if err != nil {
		return nil, errors.New("NewAESCryptor (token) failed")
	}

	uek, err := crypt.Random(32)
	if err != nil {
		return nil, errors.New("Random errored")
	}

	userCryptor, err := crypt.NewAESCryptor(uek)
	if err != nil {
		return nil, errors.New("NewAESCryptor (user) failed")
	}

	gek, err := crypt.Random(32)
	if err != nil {
		return nil, errors.New("Random errored")
	}

	groupCryptor, err := crypt.NewAESCryptor(gek)
	if err != nil {
		return nil, errors.New("NewAESCryptor (group) failed")
	}

	userAuthenticator := &UserAuthenticator{
		TokenCryptor: tokenCryptor,
		UserCryptor:  userCryptor,
		GroupCryptor: groupCryptor,
	}

	return userAuthenticator, nil
}

func TestNewUser(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("NewUser errored: %s", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertUserFunc: func(ctx context.Context, protected *common.ProtectedUserData) error {
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	_, _, err = userAuthenticator.NewUser(ctx)
	failOnError("Expected NewUser to succeed", err, t)
}

func TestUpdateUser(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("UpdateUser errored: %s", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		UpdateUserFunc: func(ctx context.Context, protected *common.ProtectedUserData) error {
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	err = userAuthenticator.UpdateUser(ctx, userID, userData)
	failOnError("Expected UpdateUser to succeed", err, t)
}

func TestGetUserData(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("GetUserData errored: %s", err)
	}

	wrappedKey, ciphertext, err := userAuthenticator.UserCryptor.EncodeAndEncrypt(userData, userID.Bytes())
	if err != nil {
		t.Fatalf("GetUserData errored: %s", err)
	}

	protected := &common.ProtectedUserData{
		UserID:     userID,
		UserData:   ciphertext,
		WrappedKey: wrappedKey,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
			return protected, nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	fetchedUserData, err := userAuthenticator.GetUserData(ctx, userID)
	failOnError("Expected GetUserData to succeed", err, t)

	if !reflect.DeepEqual(userData, fetchedUserData) {
		t.Fatalf("Fetched user data is different from original")
	}
}

func TestLoginUser(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("LoginUser errored: %s", err)
	}

	password := "Password"
	salt := []byte("Salt")
	hashedPassword := crypt.HashPassword(password, salt)
	var userData = &common.UserData{
		HashedPassword: hashedPassword,
		Salt:           salt,
		GroupIDs: map[uuid.UUID]bool{
			uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
		},
	}

	wrappedKey, ciphertext, err := userAuthenticator.UserCryptor.EncodeAndEncrypt(userData, userID.Bytes())
	if err != nil {
		t.Fatalf("LoginUser errored: %s", err)
	}

	protected := &common.ProtectedUserData{
		UserID:     userID,
		UserData:   ciphertext,
		WrappedKey: wrappedKey,
	}

	groupData := &common.GroupData{
		Scopes: common.ScopeRead,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
			return protected, nil
		},
		GetGroupDataBatchFunc: func(ctx context.Context, groupIDs []uuid.UUID) ([]common.ProtectedGroupData, error) {
			groupDataBatch := make([]common.ProtectedGroupData, 0, len(groupIDs))
			for _, groupID := range groupIDs {
				wrappedKey, ciphertext, err := userAuthenticator.GroupCryptor.EncodeAndEncrypt(groupData, groupID.Bytes())
				if err != nil {
					t.Fatalf("GetGroupDataBatch errored: %s", err)
				}

				protected := &common.ProtectedGroupData{
					GroupID:    groupID,
					GroupData:  ciphertext,
					WrappedKey: wrappedKey,
				}
				groupDataBatch = append(groupDataBatch, *protected)
			}
			return groupDataBatch, nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	_, err = userAuthenticator.LoginUser(ctx, userID, password)
	failOnError("Expected LoginUser to succeed", err, t)
}

func TestLoginUserWrongPassword(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("LoginUser errored: %s", err)
	}

	wrappedKey, ciphertext, err := userAuthenticator.UserCryptor.EncodeAndEncrypt(userData, userID.Bytes())
	if err != nil {
		t.Fatalf("GetUserData errored: %s", err)
	}

	protected := &common.ProtectedUserData{
		UserID:     userID,
		UserData:   ciphertext,
		WrappedKey: wrappedKey,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
			return protected, nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	_, err = userAuthenticator.LoginUser(ctx, userID, "password")
	failOnSuccess("Login should have failed due to wrong password", err, t)
}

func TestRemoveUserFromGroup(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("RemoveUser errored: %s", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		RemoveUserFunc: func(ctx context.Context, userID uuid.UUID) error {
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	err = userAuthenticator.RemoveUser(ctx, userID)
	failOnError("Expected RemoveUser to succeed", err, t)
}

func TestNewGroupWithID(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("NewGroupWithID errored: %s", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertGroupFunc: func(ctx context.Context, protected *common.ProtectedGroupData) error {
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	groupID := uuid.Must(uuid.NewV4())
	scopes := common.ScopeCreate
	err = userAuthenticator.NewGroupWithID(ctx, groupID, scopes)
	failOnError("Expected NewGroupWithID to succeed", err, t)
}

func TestNewGroup(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("NewGroup errored: %s", err)
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		InsertGroupFunc: func(ctx context.Context, protected *common.ProtectedGroupData) error {
			return nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	scopes := common.ScopeCreate
	_, err = userAuthenticator.NewGroup(ctx, scopes)
	failOnError("Expected NewGroup to succeed", err, t)
}

func TestGetGroupDataBatch(t *testing.T) {
	userAuthenticator, err := SetupUA()
	if err != nil {
		t.Fatalf("GetGroupDataBatch errored: %s", err)
	}

	groupData := &common.GroupData{
		Scopes: common.ScopeRead,
	}
	groupDataBatch := []common.GroupData{*groupData}

	authStoreTx := &authstorage.AuthStoreTxMock{
		GetGroupDataBatchFunc: func(ctx context.Context, groupIDs []uuid.UUID) ([]common.ProtectedGroupData, error) {
			groupDataBatch := make([]common.ProtectedGroupData, 0, len(groupIDs))
			for _, groupID := range groupIDs {
				wrappedKey, ciphertext, err := userAuthenticator.GroupCryptor.EncodeAndEncrypt(groupData, groupID.Bytes())
				if err != nil {
					t.Fatalf("GetGroupDataBatch errored: %s", err)
				}

				protected := &common.ProtectedGroupData{
					GroupID:    groupID,
					GroupData:  ciphertext,
					WrappedKey: wrappedKey,
				}
				groupDataBatch = append(groupDataBatch, *protected)
			}
			return groupDataBatch, nil
		},
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	groupID := uuid.Must(uuid.NewV4())
	groupIDs := []uuid.UUID{groupID}

	fetchedGroupDataBatch, err := userAuthenticator.GetGroupDataBatch(ctx, groupIDs)
	failOnError("Expected GetGroupDataBatch to succeed", err, t)

	if !reflect.DeepEqual(groupDataBatch, fetchedGroupDataBatch) {
		t.Fatalf("Fetched group data batch is different from original")
	}
}
