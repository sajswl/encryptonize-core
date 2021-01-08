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
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"

	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/authz"
	"encryption-service/contextkeys"
	"encryption-service/crypt"
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

func CreateUserForTests(m *crypt.MessageAuthenticator, userID uuid.UUID, scopes authn.ScopeType) (string, error) {
	authenticator := &authn.Authenticator{
		MessageAuthenticator: m,
	}

	accessToken := &authn.AccessToken{}
	err := accessToken.New(userID, scopes)
	if err != nil {
		return "", err
	}

	token, err := authenticator.SerializeAccessToken(accessToken)
	if err != nil {
		return "", err
	}

	token = "bearer " + token
	return token, nil
}

// This is a good path test of the authentication middleware
// It ONLY tests the middleware and assumes that the authn.LoginUser works as intended
func TestAuthMiddlewareGoodPath(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK)
	failOnError("NewMessageAuthenticator errored", err, t)

	token, err := CreateUserForTests(m, userID, userScope)
	failOnError("SerializeAccessToken errored", err, t)

	var md = metadata.Pairs("authorization", token)
	app := App{
		MessageAuthenticator: m,
	}

	ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = app.AuthenticateUser(ctx)
	failOnError("Auth failed", err, t)
}

func TestAuthMiddlewareNonBase64(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK)
	failOnError("NewMessageAuthenticator errored %v", err, t)

	goodToken, err := CreateUserForTests(m, userID, userScope)
	failOnError("SerializeAccessToken failed", err, t)

	goodTokenParts := strings.Split(goodToken, ".")

	app := App{
		MessageAuthenticator: m,
	}

	// for each position of the split token
	for i := 0; i < len(goodTokenParts); i++ {
		tokenParts := []string{}
		// combine both tokens such that all but the
		// position 'i' come from the first.
		for j := 0; j < len(goodTokenParts); j++ {
			if i != j {
				tokenParts = append(tokenParts, goodTokenParts[j])
			} else {
				tokenParts = append(tokenParts, "-~iamnoturlbase64+/")
			}
		}
		token := strings.Join(tokenParts, ".")

		var md = metadata.Pairs("authorization", token)
		ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/app.Encryptonize/Store")
		ctx = metadata.NewIncomingContext(ctx, md)
		_, err = app.AuthenticateUser(ctx)
		failOnSuccess("Auth should have errored", err, t)
	}
}

func TestAuthMiddlewareSwappedTokenParts(t *testing.T) {
	userIDFirst := uuid.Must(uuid.NewV4())
	userIDSecond := uuid.Must(uuid.NewV4())
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK)
	failOnError("NewMessageAuthenticator errored %v", err, t)

	tokenFirst, err := CreateUserForTests(m, userIDFirst, userScope)
	failOnError("SerializeAccessToken failed", err, t)
	tokenSecond, err := CreateUserForTests(m, userIDSecond, userScope)
	failOnError("SerializeAccessToken failed", err, t)

	firstTokenParts := strings.Split(tokenFirst, ".")
	secondTokenParts := strings.Split(tokenSecond, ".")

	app := App{
		MessageAuthenticator: m,
	}

	// for each position of the split token
	for i := 0; i < len(firstTokenParts); i++ {
		tokenParts := []string{}
		// combine both tokens such that all but the
		// position 'i' come from the first.
		for j := 0; j < len(firstTokenParts); j++ {
			if i != j {
				tokenParts = append(tokenParts, firstTokenParts[j])
			} else {
				tokenParts = append(tokenParts, secondTokenParts[j])
			}
		}
		token := strings.Join(tokenParts, ".")

		var md = metadata.Pairs("authorization", token)
		ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/app.Encryptonize/Store")
		ctx = metadata.NewIncomingContext(ctx, md)
		_, err = app.AuthenticateUser(ctx)
		failOnSuccess("Auth should have errored", err, t)
	}
}

// Tests that accesstoken of wrong type gets rejected
func TestAuthMiddlewareInvalidAT(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	userScope := authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK)
	failOnError("NewMessageAuthenticator errored", err, t)

	token, err := CreateUserForTests(m, userID, userScope)
	failOnError("SerializeAccessToken errored", err, t)

	token = "notBearer" + token[6:]
	var md = metadata.Pairs("authorization", token)
	app := App{
		MessageAuthenticator: m,
	}

	ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/app.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = app.AuthenticateUser(ctx)
	failOnSuccess("Auth should have failed", err, t)
}

// Tests that accesstoken thats not hex gets rejected
func TestAuthMiddlewareInvalidATformat(t *testing.T) {
	app := App{}

	// Test wrong format AT
	// User credentials
	AT := "bearer thisIsANonHexaDecimalSentenceThatsAtLeastSixtyFourCharactersLong"
	var md = metadata.Pairs("authorization", AT)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, "/app.Encryptonize/Store")
	_, err := app.AuthenticateUser(ctx)
	failOnSuccess("Invalid Auth Passed", err, t)

	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// This test tries to access each endpoint with every but the required scope
// all tests should fail
func TestAuthMiddlewareNegativeScopes(t *testing.T) {
	ASK, _ := crypt.Random(32)
	m, err := crypt.NewMessageAuthenticator(ASK)
	failOnError("Error creating MessageAuthenticator", err, t)

	app := App{
		MessageAuthenticator: m,
	}

	for endpoint, rscope := range methodScopeMap {
		if rscope == authn.ScopeNone {
			// endpoints that only require logged in users are already covered
			// by tests that check if authentication works
			continue
		}
		tscopes := (authn.ScopeEnd - 1) &^ rscope
		tuid := uuid.Must(uuid.NewV4())
		token, err := CreateUserForTests(m, tuid, tscopes)
		failOnError("Error Creating User", err, t)

		var md = metadata.Pairs("authorization", token)

		ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, endpoint)
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
	failOnError("Couldn't generate WOEK!", err, t)

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
	failOnError("NewMessageAuthenticator errored", err, t)

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageCtxKey, authnStorageMock)

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
	failOnError("Couldn't generate WOEK!", err, t)

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
	failOnError("NewMessageAuthenticator errored", err, t)

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageCtxKey, authnStorageMock)

	authorizer, accessObject, err := AuthorizeWrapper(ctx, messageAuthenticator, objectID.String())
	failOnSuccess("User should not be authorized", err, t)

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
