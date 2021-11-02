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
	"testing"

	"context"
	"errors"
	"reflect"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/interfaces"
	"encryption-service/users"
)

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

type AuthorizerMock struct {
	accessObject *authzimpl.AccessObject
}

func (a *AuthorizerMock) CreateAccessObject(_ context.Context, _, _ uuid.UUID, _ []byte) error {
	return nil
}

func (a *AuthorizerMock) FetchAccessObject(ctx context.Context, objectID uuid.UUID) (interfaces.AccessObjectInterface, error) {
	if a.accessObject == nil {
		return nil, errors.New("No object")
	}
	return a.accessObject, nil
}

func (a *AuthorizerMock) UpsertAccessObject(_ context.Context, _ uuid.UUID, _ interfaces.AccessObjectInterface) error {
	return nil
}

func (a *AuthorizerMock) DeleteAccessObject(_ context.Context, _ uuid.UUID) error {
	return nil
}

type UserAuthenticatorMock struct {
	userData *users.ConfidentialUserData
}

func (u *UserAuthenticatorMock) NewUser(_ context.Context, _ users.ScopeType) (*uuid.UUID, string, error) {
	return &uuid.Nil, "", nil
}

func (u *UserAuthenticatorMock) NewCLIUser(_ string, _ interfaces.AuthStoreInterface) error {
	return nil
}

func (u *UserAuthenticatorMock) ParseAccessToken(_ string) (interfaces.AccessTokenInterface, error) {
	return nil, nil
}

func (u *UserAuthenticatorMock) LoginUser(_ context.Context, _ uuid.UUID, _ string) (string, error) {
	return "", nil
}

func (u *UserAuthenticatorMock) RemoveUser(_ context.Context, _ uuid.UUID) error {
	return nil
}

func (u *UserAuthenticatorMock) GetUserData(ctx context.Context, userID uuid.UUID) (*users.ConfidentialUserData, error) {
	if u.userData == nil {
		return nil, errors.New("No data")
	}
	return u.userData, nil
}

func SetupMocks(methodName string, userID, objectID uuid.UUID, accessObject *authzimpl.AccessObject, userData *users.ConfidentialUserData) (context.Context, *Authz) {
	ctx := context.Background()

	if userID != uuid.Nil {
		ctx = context.WithValue(ctx, contextkeys.UserIDCtxKey, userID)
	}
	if objectID != uuid.Nil {
		ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectID)
	}
	if methodName != "" {
		ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, methodName)
	}

	authz := &Authz{
		Authorizer:        &AuthorizerMock{accessObject: accessObject},
		UserAuthenticator: &UserAuthenticatorMock{userData: userData},
	}

	return ctx, authz
}

func TestAuthzMiddleware(t *testing.T) {
	methodName := "fake method"
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}

	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		accessObjectFetched, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(interfaces.AccessObjectInterface)
		if !ok {
			t.Fatal("Access object not added to context")
		}

		if !reflect.DeepEqual(accessObject, accessObjectFetched) {
			t.Fatal("Access object in context not equal to original")
		}

		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnError("Expected user to be authorized", err, t)
}

func TestAuthzMiddlewareUnauthorized(t *testing.T) {
	methodName := "fake method"
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("User should not be authorized", err, t)

	if errStatus, _ := status.FromError(err); codes.PermissionDenied != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.PermissionDenied, errStatus)
	}
}

func TestAuthzNoAccessObject(t *testing.T) {
	methodName := "fake method"
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, nil, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("User should not be authorized", err, t)

	if errStatus, _ := status.FromError(err); codes.NotFound != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.NotFound, errStatus)
	}
}

func TestAuthzNoUserData(t *testing.T) {
	methodName := "fake method"
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, nil)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("User should not be authorized", err, t)

	if errStatus, _ := status.FromError(err); codes.NotFound != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.NotFound, errStatus)
	}
}

func TestAuthzNoMethod(t *testing.T) {
	methodName := ""
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("User should not be authorized", err, t)

	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestAuthzNoUserID(t *testing.T) {
	methodName := "fake method"
	userID := uuid.Nil
	objectID := uuid.Must(uuid.NewV4())
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("User should not be authorized", err, t)

	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestAuthzNoObjectID(t *testing.T) {
	methodName := "fake method"
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Nil
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("User should not be authorized", err, t)

	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestAuthzSkippedMethod(t *testing.T) {
	methodName := "/app.Encryptonize/Version"
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Nil
	accessObject := &authzimpl.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	}
	userData := &users.ConfidentialUserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}

	// Test
	ctx, authz := SetupMocks(methodName, userID, objectID, accessObject, userData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		_, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(interfaces.AccessObjectInterface)
		if ok {
			t.Fatal("Found unexpected access object in context")
		}
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnError("Expected authorization to be skipped", err, t)
}
