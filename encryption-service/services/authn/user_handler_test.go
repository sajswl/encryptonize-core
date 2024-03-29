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
	fmt "fmt"
	"testing"

	"context"
	"errors"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/common"
	authnimpl "encryption-service/impl/authn"
	"encryption-service/impl/authstorage"
	"encryption-service/interfaces"
)

var outputUserData = &common.UserData{
	HashedPassword: []byte("HashedPassword"),
	Salt:           []byte("Salt"),
	GroupIDs: map[uuid.UUID]bool{
		uuid.FromStringOrNil("10000000-0000-0000-0000-000000000000"): true,
	},
}

func TestCreateUser(t *testing.T) {
	outputUserID := uuid.Must(uuid.NewV4())
	password := "Password"
	readScope := []common.Scope{common.Scope_READ}
	updateUserCall := false
	getUserDataCall := false
	newGroupWithIDCall := false

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		NewUserFunc: func(ctx context.Context) (*uuid.UUID, string, error) {
			return &outputUserID, password, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			updateUserCall = true
			if userID != outputUserID {
				return errors.New("User ID is incorrect")
			}
			if userData != outputUserData {
				return errors.New("User data is incorrect")
			}
			return nil
		},
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			getUserDataCall = true
			if userID != outputUserID {
				return nil, errors.New("User ID is incorrect")
			}
			return outputUserData, nil
		},
		NewGroupWithIDFunc: func(ctx context.Context, groupID uuid.UUID, scopes common.ScopeType) error {
			newGroupWithIDCall = true
			if groupID != outputUserID {
				return errors.New("Group ID is incorrect")
			}
			if !scopes.HasScopes(common.ScopeType(common.Scope_READ)) {
				return errors.New("Scope is incorrect")
			}
			return nil
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	request := CreateUserRequest{
		Scopes: readScope,
	}

	response, err := authn.CreateUser(ctx, &request)
	if err != nil {
		t.Fatalf("CreateUser failed: %s", err)
	}
	if response.UserId != outputUserID.String() {
		t.Fatalf("Expected user ID %s but got %s", outputUserID.String(), response.UserId)
	}

	if !updateUserCall {
		t.Fatal("Failed to update user")
	}
	if !getUserDataCall {
		t.Fatal("Failed to get user data")
	}
	if !newGroupWithIDCall {
		t.Fatal("Failed to create a group correspondent to the user")
	}
}

func TestFailCreateUser(t *testing.T) {
	outputUserID := uuid.Must(uuid.NewV4())
	password := "Password"

	var errors = [][]error{
		{errors.New("NewUser errored"), nil, nil, nil},
		{nil, errors.New("NewGroupWithID errored"), nil, nil},
		{nil, nil, errors.New("GetUserData errored"), nil},
		{nil, nil, nil, errors.New("UpdateUser errored")},
	}
	for _, err := range errors {
		t.Run(fmt.Sprintf("Error%s", err), func(t *testing.T) {
			userAuthenticator := &authnimpl.UserAuthenticatorMock{
				NewUserFunc: func(ctx context.Context) (*uuid.UUID, string, error) {
					return &outputUserID, password, err[0]
				},
				UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
					return err[1]
				},
				GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
					return outputUserData, err[2]
				},
				NewGroupWithIDFunc: func(ctx context.Context, groupID uuid.UUID, scopes common.ScopeType) error {
					return err[3]
				},
			}

			authn := Authn{
				UserAuthenticator: userAuthenticator,
			}

			authStoreTx := &authstorage.AuthStoreTxMock{
				CommitFunc: func(ctx context.Context) error { return nil },
			}
			ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

			request := CreateUserRequest{
				Scopes: []common.Scope{common.Scope_READ},
			}

			_, err := authn.CreateUser(ctx, &request)
			if err == nil {
				t.Fatalf("Expected CreateUser to fail")
			}
			if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
				t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
			}
		})
	}
}

func TestCreateUserFailToCommit(t *testing.T) {
	outputUserID := uuid.Must(uuid.NewV4())
	password := "Password"

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		NewUserFunc: func(ctx context.Context) (*uuid.UUID, string, error) {
			return &outputUserID, password, nil
		},
		UpdateUserFunc: func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
			return nil
		},
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			return outputUserData, nil
		},
		NewGroupWithIDFunc: func(ctx context.Context, groupID uuid.UUID, scopes common.ScopeType) error {
			return nil
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return errors.New("Commit errored") },
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	request := CreateUserRequest{
		Scopes: []common.Scope{common.Scope_READ},
	}

	_, err := authn.CreateUser(ctx, &request)
	if err == nil {
		t.Fatalf("Expected CreateUser to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestLoginUser(t *testing.T) {
	loginUserID := uuid.Must(uuid.NewV4())
	loginPassword := "password"
	outputToken := "token"
	loginUserCall := false

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		LoginUserFunc: func(ctx context.Context, userID uuid.UUID, password string) (string, error) {
			loginUserCall = true
			if userID != loginUserID {
				return "", errors.New("User ID is incorrect")
			}
			if password != loginPassword {
				return "", errors.New("Password is incorrect")
			}
			return outputToken, nil
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	request := LoginUserRequest{
		UserId:   loginUserID.String(),
		Password: loginPassword,
	}

	response, err := authn.LoginUser(context.Background(), &request)
	if err != nil {
		t.Fatalf("LoginUser failed: %s", err)
	}
	if response.AccessToken != outputToken {
		t.Fatalf("Expected token %s but got %s", outputToken, response.AccessToken)
	}
	if !loginUserCall {
		t.Fatal("Failed to log in user")
	}
}

func TestFailLoginUser(t *testing.T) {
	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		LoginUserFunc: func(ctx context.Context, userID uuid.UUID, password string) (string, error) {
			return "", errors.New("LoginUser errored")
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	userID := uuid.Must(uuid.NewV4())
	request := LoginUserRequest{
		UserId:   userID.String(),
		Password: "password",
	}

	_, err := authn.LoginUser(context.Background(), &request)
	if err == nil {
		t.Fatalf("Expected LoginUser to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestRemoveUser(t *testing.T) {
	target := uuid.Must(uuid.NewV4())
	removeUserCall := false

	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		RemoveUserFunc: func(ctx context.Context, userID uuid.UUID) error {
			removeUserCall = true
			if userID != target {
				return errors.New("User ID does not match with the target")
			}
			return nil
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	request := RemoveUserRequest{
		UserId: target.String(),
	}

	_, err := authn.RemoveUser(ctx, &request)
	if err != nil {
		t.Fatalf("RemoveUser failed: %s", err)
	}
	if !removeUserCall {
		t.Fatal("Failed to remove user")
	}
}

func TestRemoveUserNotFound(t *testing.T) {
	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		RemoveUserFunc: func(ctx context.Context, userID uuid.UUID) error {
			return interfaces.ErrNotFound
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	target := uuid.Must(uuid.NewV4())
	request := RemoveUserRequest{
		UserId: target.String(),
	}

	_, err := authn.RemoveUser(ctx, &request)
	if err == nil {
		t.Fatalf("Expected RemoveUser to fail")
	}
	if errStatus, _ := status.FromError(err); codes.NotFound != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.NotFound, errStatus)
	}
}

func TestRemoveUserUnknown(t *testing.T) {
	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		RemoveUserFunc: func(ctx context.Context, userID uuid.UUID) error {
			return errors.New("RemoveUser errored")
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return nil },
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	target := uuid.Must(uuid.NewV4())
	request := RemoveUserRequest{
		UserId: target.String(),
	}

	_, err := authn.RemoveUser(ctx, &request)
	if err == nil {
		t.Fatalf("Expected RemoveUser to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestRemoveUserFailToCommit(t *testing.T) {
	userAuthenticator := &authnimpl.UserAuthenticatorMock{
		RemoveUserFunc: func(ctx context.Context, userID uuid.UUID) error {
			return nil
		},
	}
	authn := Authn{
		UserAuthenticator: userAuthenticator,
	}

	authStoreTx := &authstorage.AuthStoreTxMock{
		CommitFunc: func(ctx context.Context) error { return errors.New("Commit errored") },
	}
	ctx := context.WithValue(context.Background(), common.AuthStorageTxCtxKey, authStoreTx)

	target := uuid.Must(uuid.NewV4())
	request := RemoveUserRequest{
		UserId: target.String(),
	}

	_, err := authn.RemoveUser(ctx, &request)
	if err == nil {
		t.Fatalf("Expected RemoveUser to fail")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}
