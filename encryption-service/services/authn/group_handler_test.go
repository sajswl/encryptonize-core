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
	"reflect"
	"testing"

	"context"
	"errors"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/common"
	authnimpl "encryption-service/impl/authn"
	"encryption-service/impl/authstorage"
)

func TestCreateGroup(t *testing.T) {
	inputScopes := common.ScopeRead
	outputGroupID := uuid.Must(uuid.NewV4())

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		NewGroupFunc: func(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, error) {
			if scopes != inputScopes {
				t.Fatalf("Expected scopes %d but got %d", inputScopes, scopes)
			}

			return &outputGroupID, nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	request := CreateGroupRequest{
		Scopes: []common.Scope{common.Scope_READ},
	}

	response, err := authn.CreateGroup(ctx, &request)
	if err != nil {
		t.Fatalf("CreateGroup failed: %s", err)
	}
	if response.GroupId != outputGroupID.String() {
		t.Fatalf("Expected group ID %s but got %s", outputGroupID.String(), response.GroupId)
	}
}

func TestCreateGroupWrongScope(t *testing.T) {
	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		NewGroupFunc: func(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, error) {
			t.Fatalf("Did not expect NewGroup to be called")
			return nil, nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	request := CreateGroupRequest{
		Scopes: []common.Scope{739397},
	}

	_, err := authn.CreateGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected CreateGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}
}

func TestCreateGroupUserAuthFail(t *testing.T) {
	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		NewGroupFunc: func(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, error) {
			return nil, errors.New("Mock error")
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	request := CreateGroupRequest{
		Scopes: []common.Scope{common.Scope_READ},
	}

	_, err := authn.CreateGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected CreateGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestAddUserToGroup(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())
	outputUserData := &common.UserData{
		HashedPassword: []byte("HashedPassword"),
		Salt:           []byte("Salt"),
		GroupIDs: map[uuid.UUID]bool{
			uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
		},
	}
	expectedUserData := &common.UserData{
		HashedPassword: outputUserData.HashedPassword,
		Salt:           outputUserData.Salt,
		GroupIDs: map[uuid.UUID]bool{
			uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
			inputGroupID: true,
		},
	}

	authStoreTxMock := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
		GroupExistsFunc: func(ctx context.Context, groupID uuid.UUID) (bool, error) {
			if inputGroupID != groupID {
				t.Fatalf("Expected group ID %s but got %s", inputGroupID, groupID)
			}
			return true, nil
		},
	}

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			if inputUserID != userID {
				t.Fatalf("Expected user ID %s but got %s", inputGroupID, userID)
			}
			return outputUserData, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			if inputUserID != userID {
				t.Fatalf("Expected user ID %s but got %s", inputGroupID, userID)
			}
			if !reflect.DeepEqual(userData, expectedUserData) {
				t.Fatalf("Updated user data not equal to expected: %+v != %+v", expectedUserData, userData)
			}
			return nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTxMock)

	request := AddUserToGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: inputGroupID.String(),
	}

	_, err := authn.AddUserToGroup(ctx, &request)
	if err != nil {
		t.Fatalf("AddUserToGroup failed: %s", err)
	}
}

func TestAddUserToGroupNoTx(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())
	outputUserData := &common.UserData{
		HashedPassword: []byte("HashedPassword"),
		Salt:           []byte("Salt"),
		GroupIDs: map[uuid.UUID]bool{
			uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
		},
	}

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			return outputUserData, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			return nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	request := AddUserToGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: inputGroupID.String(),
	}

	_, err := authn.AddUserToGroup(context.Background(), &request)
	if err == nil {
		t.Fatalf("Expected AddUserToGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestAddUserToGroupWrongArgs(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())
	outputUserData := &common.UserData{
		HashedPassword: []byte("HashedPassword"),
		Salt:           []byte("Salt"),
		GroupIDs: map[uuid.UUID]bool{
			uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
		},
	}

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			return outputUserData, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			return nil
		},
	}
	authStoreTxMock := &authstorage.AuthStoreTxMock{
		GroupExistsFunc: func(ctx context.Context, groupID uuid.UUID) (bool, error) {
			return false, nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTxMock)

	// Invalid user ID
	request := AddUserToGroupRequest{
		UserId:  "foo",
		GroupId: inputGroupID.String(),
	}
	_, err := authn.AddUserToGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected AddUserToGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}

	// Invalid group ID
	request = AddUserToGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: "foo",
	}
	_, err = authn.AddUserToGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected AddUserToGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}

	// Group doesn't exist
	request = AddUserToGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: inputGroupID.String(),
	}
	_, err = authn.AddUserToGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected AddUserToGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}
}

func TestAddUserToGroupNoUser(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			return nil, errors.New("Mock error")
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			return nil
		},
	}
	authStoreTxMock := &authstorage.AuthStoreTxMock{
		GroupExistsFunc: func(ctx context.Context, groupID uuid.UUID) (bool, error) {
			return true, nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTxMock)

	request := AddUserToGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: inputGroupID.String(),
	}
	_, err := authn.AddUserToGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected AddUserToGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}
}

func TestRemoveUserFromGroup(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())
	outputUserData := &common.UserData{
		HashedPassword: []byte("HashedPassword"),
		Salt:           []byte("Salt"),
		GroupIDs: map[uuid.UUID]bool{
			inputGroupID: true,
		},
	}
	expectedUserData := &common.UserData{
		HashedPassword: outputUserData.HashedPassword,
		Salt:           outputUserData.Salt,
		GroupIDs:       map[uuid.UUID]bool{},
	}

	authStoreTxMock := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			if inputUserID != userID {
				t.Fatalf("Expected user ID %s but got %s", inputGroupID, userID)
			}
			return outputUserData, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			if inputUserID != userID {
				t.Fatalf("Expected user ID %s but got %s", inputGroupID, userID)
			}
			if !reflect.DeepEqual(userData, expectedUserData) {
				t.Fatalf("Updated user data not equal to expected: %+v != %+v", expectedUserData, userData)
			}
			return nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTxMock)

	request := RemoveUserFromGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: inputGroupID.String(),
	}

	_, err := authn.RemoveUserFromGroup(ctx, &request)
	if err != nil {
		t.Fatalf("RemoveUserFromGroup failed: %s", err)
	}
}

func TestRemoveUserFromGroupNoTx(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())
	outputUserData := &common.UserData{
		HashedPassword: []byte("HashedPassword"),
		Salt:           []byte("Salt"),
		GroupIDs: map[uuid.UUID]bool{
			uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
		},
	}

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			return outputUserData, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			return nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	request := RemoveUserFromGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: inputGroupID.String(),
	}

	_, err := authn.RemoveUserFromGroup(context.Background(), &request)
	if err == nil {
		t.Fatalf("Expected RemoveUserFromGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestRemoveUserFromGroupWrongArgs(t *testing.T) {
	inputUserID := uuid.Must(uuid.NewV4())
	inputGroupID := uuid.Must(uuid.NewV4())
	outputUserData := &common.UserData{
		HashedPassword: []byte("HashedPassword"),
		Salt:           []byte("Salt"),
		GroupIDs: map[uuid.UUID]bool{
			inputGroupID: true,
		},
	}

	authStoreTxMock := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			if inputUserID != userID {
				return nil, errors.New("Mock error")
			}
			return outputUserData, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			return nil
		},
	}

	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTxMock)

	// Invalid user ID
	request := RemoveUserFromGroupRequest{
		UserId:  "foo",
		GroupId: inputGroupID.String(),
	}
	_, err := authn.RemoveUserFromGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected RemoveUserFromGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}

	// Invalid group ID
	request = RemoveUserFromGroupRequest{
		UserId:  inputUserID.String(),
		GroupId: "foo",
	}
	_, err = authn.RemoveUserFromGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected RemoveUserFromGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}

	// Wrong user ID
	request = RemoveUserFromGroupRequest{
		UserId:  uuid.Must(uuid.NewV4()).String(),
		GroupId: inputGroupID.String(),
	}
	_, err = authn.RemoveUserFromGroup(ctx, &request)
	if err == nil {
		t.Fatalf("Expected RemoveUserFromGroup to fail")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.InvalidArgument, errStatus)
	}
}
