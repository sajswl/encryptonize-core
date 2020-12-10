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
package app

import (
	"context"
	"encoding/hex"
	"errors"
	"strconv"
	"testing"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"

	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/authz"
	"encryption-service/crypt"
)

// This is a good path test of the authentication middleware
// It ONLY tests the middleware and assumes that the authn.LoginUser works as intended
func TestAuthMiddlewareGoodPath(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	accessToken, _ := crypt.Random(32)
	AT := "bearer " + hex.EncodeToString(accessToken)
	ASK, _ := crypt.Random(32)
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions

	var md = metadata.Pairs(
		"authorization", AT,
		"userID", userID.String(),
		"userScopes", strconv.FormatUint(uint64(userScope), 10))

	authnStorageMock := authstorage.NewMemoryAuthStore()

	m, err := crypt.NewMessageAuthenticator(ASK)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored %v", err)
	}

	// create new user
	authenticator := &authn.Authenticator{
		MessageAuthenticator: m,
		AuthStore:            authnStorageMock,
	}

	err = authenticator.CreateOrUpdateUser(context.Background(), userID, accessToken, userScope)
	if err != nil {
		t.Fatalf("CreateOrUpdateUser errored %v", err)
	}

	app := App{
		MessageAuthenticator: m,
	}

	ctx := context.WithValue(context.Background(), authStorageCtxKey, authnStorageMock)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = app.AuthenticateUser(ctx)
	if err != nil {
		t.Errorf("Auth failed: %v", err)
	}
}

func TestAuthMiddlewareWrongAT(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	accessToken, _ := crypt.Random(32)
	AT := "bearer " + hex.EncodeToString(accessToken)
	accessToken, _ = crypt.Random(32)
	ASK, _ := crypt.Random(32)
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions

	var md = metadata.Pairs(
		"authorization", AT,
		"userID", userID.String(),
		"userScopes", strconv.FormatUint(uint64(userScope), 10))

	authnStorageMock := authstorage.NewMemoryAuthStore()

	m, err := crypt.NewMessageAuthenticator(ASK)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored %v", err)
	}

	// create new user
	authentiator := &authn.Authenticator{
		MessageAuthenticator: m,
		AuthStore:            authnStorageMock,
	}

	err = authentiator.CreateOrUpdateUser(context.Background(), userID, accessToken, userScope)
	if err != nil {
		t.Fatalf("CreateOrUpdateUser errored %v", err)
	}

	app := App{
		MessageAuthenticator: m,
	}

	ctx := context.WithValue(context.Background(), authStorageCtxKey, authnStorageMock)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = app.AuthenticateUser(ctx)
	if err == nil {
		t.Fatalf("Auth should have errored")
	}
}

func TestAuthMiddlewareNonExistingUser(t *testing.T) {
	// User credentials
	UID := "bc21fe7e-fd3b-41ee-83df-000000000000"
	AT := "bearer 4141414141414141414141414141414141414141414141414141414141414141"
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))

	authnStorageMock := &authstorage.AuthStoreMock{
		GetUserTagFunc: func(ctx context.Context, userID uuid.UUID) ([]byte, error) {
			return nil, authstorage.ErrNoRows
		},
	}
	app := App{}

	ctx := context.WithValue(context.Background(), authStorageCtxKey, authnStorageMock)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Fatalf("Auth should have errored")
	}
}

// This function tests the authentication middleware
// It ONLY tests the middleware and assumes that the authn.LoginUser works as intended
func TestAuthMiddlewareInvalidUUID(t *testing.T) {
	UID := "NotEvenClose to being valid"
	AT := "bearer ed287c3a1b3f96a7be3f552890171e4785f8f787ff2c6cbebb97148cf6411783"
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	// User credentials
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))

	app := App{}

	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// Tests that a missing AT results in unauthenticated response
func TestAuthMiddlewareMissingAT(t *testing.T) {
	app := App{}

	// Test wrong format AT
	// User credentials
	UID := uuid.Must(uuid.NewV4()).String()
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	var md = metadata.Pairs(
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// Tests that accesstoken of wrong type gets rejected
func TestAuthMiddlewareInvalidAT(t *testing.T) {
	app := App{}

	// Test wrong format AT
	// User credentials
	UID := uuid.Must(uuid.NewV4()).String()
	AT := "notBearer ed287c3a1b3f96a7be3f552890171e4785f8f787ff2c6cbebb97148cf6411783"
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// Tests that accesstoken thats not hex gets rejected
func TestAuthMiddlewareInvalidATformat(t *testing.T) {
	app := App{}

	// Test wrong format AT
	// User credentials
	UID := uuid.Must(uuid.NewV4()).String()
	AT := "bearer thisIsANonHexaDecimalSentenceThatsAtLeastSixtyFourCharactersLong"
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// Tests that missing scopes results in unauthenticated response
func TestAuthMiddlewareMissingScopes(t *testing.T) {
	app := App{}

	// Test wrong format AT
	// User credentials
	UID := uuid.Must(uuid.NewV4()).String()
	AT := "bearer ed287c3a1b3f96a7be3f552890171e4785f8f787ff2c6cbebb97148cf6411783"
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// Tests that accesstoken of wrong type gets rejected
func TestAuthMiddlewareInvalidScopes(t *testing.T) {
	app := App{}

	// Test wrong format AT
	// User credentials
	UID := uuid.Must(uuid.NewV4()).String()
	AT := "bearer ed287c3a1b3f96a7be3f552890171e4785f8f787ff2c6cbebb97148cf6411783"
	userScope := authn.ScopeType(0xff)
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// Tests that accesstoken thats not hex gets rejected
func TestAuthMiddlewareInvalidModifiedScopes(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	accessToken, _ := crypt.Random(32)
	AT := "bearer " + hex.EncodeToString(accessToken)
	ASK, _ := crypt.Random(32)
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions

	var md = metadata.Pairs(
		"authorization", AT,
		"userID", userID.String(),
		"userScopes", strconv.FormatUint(uint64(userScope|authn.ScopeUserManagement), 10))

	authnStorageMock := authstorage.NewMemoryAuthStore()

	m, err := crypt.NewMessageAuthenticator(ASK)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored %v", err)
	}

	// create new user
	authenticator := &authn.Authenticator{
		MessageAuthenticator: m,
		AuthStore:            authnStorageMock,
	}

	err = authenticator.CreateOrUpdateUser(context.Background(), userID, accessToken, userScope)
	if err != nil {
		t.Fatalf("CreateOrUpdateUser errored %v", err)
	}

	app := App{
		MessageAuthenticator: m,
	}

	ctx := context.WithValue(context.Background(), authStorageCtxKey, authnStorageMock)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = app.AuthenticateUser(ctx)
	if err == nil {
		t.Fatalf("Auth should have errored")
	}
}

// Tests that if authn.LoginUser fails, then so will the authmiddleware
func TestAuthMiddlewareLoginFail(t *testing.T) {
	// User credentials
	UID := uuid.Must(uuid.NewV4()).String()
	AT := "bearer ed287c3a1b3f96a7be3f552890171e4785f8f787ff2c6cbebb97148cf6411783"
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", UID,
		"userScopes", strconv.FormatUint(uint64(userScope), 10))

	authnStorageMock := &authstorage.AuthStoreMock{
		GetUserTagFunc: func(ctx context.Context, userID uuid.UUID) ([]byte, error) {
			return nil, errors.New("mocked error")
		},
	}

	app := App{}

	ctx := context.WithValue(context.Background(), authStorageCtxKey, authnStorageMock)
	ctx = context.WithValue(ctx, methodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err := app.AuthenticateUser(ctx)
	if err == nil {
		t.Errorf("Invalid Auth Passed\n")
	}
	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.Internal, errStatus.Code())
	}
}

func InitTest() (*authstorage.MemoryAuthStore, uuid.UUID, []byte, string, *crypt.MessageAuthenticator, error) {
	userID := uuid.Must(uuid.NewV4())
	accessToken, _ := crypt.Random(32)
	AT := "bearer " + hex.EncodeToString(accessToken)
	ASK, _ := crypt.Random(32)

	authnStorageMock := authstorage.NewMemoryAuthStore()

	m, err := crypt.NewMessageAuthenticator(ASK)
	if err != nil {
		return nil, uuid.UUID{}, nil, "", nil, err
	}

	return authnStorageMock, userID, accessToken, AT, m, nil
}

func CreateUserForTests(authStore authstorage.AuthStoreInterface, m *crypt.MessageAuthenticator, userID uuid.UUID, accessToken []byte, scopes authn.ScopeType) (metadata.MD, error) {
	AT := "bearer " + hex.EncodeToString(accessToken)
	var md = metadata.Pairs(
		"authorization", AT,
		"userID", userID.String(),
		"userScopes", strconv.FormatUint(uint64(scopes), 10))

	authenticator := &authn.Authenticator{
		MessageAuthenticator: m,
		AuthStore:            authStore,
	}
	return md, authenticator.CreateOrUpdateUser(context.Background(), userID, accessToken, scopes)
}

// This test tries to access each endpoint with every but the required scope
// all tests should fail
func TestAuthMiddlewareNegativeScopes(t *testing.T) {
	authnStorageMock, _, _, _, m, err := InitTest()
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored %v", err)
	}

	app := App{
		MessageAuthenticator: m,
	}

	for endpoint, rscope := range methodScopeMap {
		tscopes := (authn.ScopeEnd - 1) &^ rscope
		tuid := uuid.Must(uuid.NewV4())
		taccessToken, _ := crypt.Random(32)
		md, err := CreateUserForTests(authnStorageMock, m, tuid, taccessToken, tscopes)
		if err != nil {
			t.Fatalf("CreateOrUpdateUser errored %v", err)
		}

		ctx := context.WithValue(context.Background(), authStorageCtxKey, authnStorageMock)
		ctx = context.WithValue(ctx, methodNameCtxKey, endpoint)
		ctx = metadata.NewIncomingContext(ctx, md)
		_, err = app.AuthenticateUser(ctx)
		if err == nil {
			t.Errorf("User allowed to call endpoint %v requireing scopes %v using scopes %v", endpoint, rscope, tscopes)
		}
	}
}

func TestAuthorizeWrapper(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	Woek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Couldn't generate WOEK!\n")
	}
	accessObject := &authz.AccessObject{
		UserIds: [][]byte{
			userID.Bytes(),
		},
		Woek:    Woek,
		Version: 0,
	}

	authnStorageMock := &authstorage.AuthStoreMock{
		GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
			data, tag, err := authorizer.SerializeAccessObject(objectID, accessObject)
			return data, tag, err
		},
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return nil
		},
	}
	messageAuthenticator, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored %v", err)
	}

	ctx := context.WithValue(context.Background(), userIDCtxKey, userID)
	ctx = context.WithValue(ctx, authStorageCtxKey, authnStorageMock)

	authorizer, accessObject, err := AuthorizeWrapper(ctx, messageAuthenticator, objectID.String())
	if err != nil {
		t.Fatalf("User couldn't be authorized")
	}
	if authorizer == nil {
		t.Fatalf("Authorizer is nil, but no error")
	}
	if accessObject == nil {
		t.Fatalf("Access object is nil but no error")
	}
}

func TestAuthorizeWrapperUnauthorized(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	Woek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Couldn't generate WOEK!\n")
	}

	unAuthAccessObject := &authz.AccessObject{
		UserIds: [][]byte{
			uuid.Must(uuid.NewV4()).Bytes(),
		},
		Woek:    Woek,
		Version: 0,
	}

	authnStorageMock := &authstorage.AuthStoreMock{
		GetAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
			data, tag, err := authorizer.SerializeAccessObject(objectID, unAuthAccessObject)
			return data, tag, err
		},
		UpdateAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
			return nil
		},
	}

	messageAuthenticator, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored %v", err)
	}

	ctx := context.WithValue(context.Background(), userIDCtxKey, userID)
	ctx = context.WithValue(ctx, authStorageCtxKey, authnStorageMock)

	authorizer, accessObject, err := AuthorizeWrapper(ctx, messageAuthenticator, objectID.String())
	if err == nil {
		t.Fatalf("User should not be authorized")
	}
	if errStatus, _ := status.FromError(err); codes.PermissionDenied != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.PermissionDenied, errStatus)
	}
	if authorizer != nil {
		t.Fatalf("Leaking authorizer data")
	}
	if accessObject != nil {
		t.Fatalf("Leaking access object data")
	}
}
