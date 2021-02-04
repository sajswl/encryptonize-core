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

package authn

import (
	"context"
	"strings"
	"testing"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	status "google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/impl/authn"
	authnimpl "encryption-service/impl/authn"
	"encryption-service/impl/crypt"
	"encryption-service/scopes"
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

func CreateUserForTests(m *crypt.MessageAuthenticator, userID uuid.UUID, scopes scopes.ScopeType) (string, error) {
	accessToken := authnimpl.NewAccessToken(userID, scopes)

	token, err := accessToken.SerializeAccessToken(m)
	if err != nil {
		return "", err
	}

	token = "bearer " + token
	return token, nil
}

// This is a good path test of the authentication middleware
// It ONLY tests the middleware and assumes that the LoginUser works as intended
func TestCheckAccessTokenGoodPath(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	userScope := scopes.ScopeRead | scopes.ScopeCreate | scopes.ScopeIndex | scopes.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK, crypt.TokenDomain)
	failOnError("NewMessageAuthenticator errored", err, t)

	token, err := CreateUserForTests(m, userID, userScope)
	failOnError("SerializeAccessToken errored", err, t)

	var md = metadata.Pairs("authorization", token)
	au := &AuthnService{
		UserAuthenticator: &authn.UserAuthenticator{Authenticator: m},
	}

	ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/enc.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = au.CheckAccessToken(ctx)
	failOnError("Auth failed", err, t)
}

func TestCheckAccessTokenNonBase64(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	userScope := scopes.ScopeRead | scopes.ScopeCreate | scopes.ScopeIndex | scopes.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK, crypt.TokenDomain)
	failOnError("NewMessageAuthenticator errored %v", err, t)

	goodToken, err := CreateUserForTests(m, userID, userScope)
	failOnError("SerializeAccessToken failed", err, t)

	goodTokenParts := strings.Split(goodToken, ".")

	au := &AuthnService{
		UserAuthenticator: &authn.UserAuthenticator{Authenticator: m},
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
		ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/enc.Encryptonize/Store")
		ctx = metadata.NewIncomingContext(ctx, md)
		_, err = au.CheckAccessToken(ctx)
		failOnSuccess("Auth should have errored", err, t)
	}
}

func TestCheckAccessTokenSwappedTokenParts(t *testing.T) {
	userIDFirst := uuid.Must(uuid.NewV4())
	userIDSecond := uuid.Must(uuid.NewV4())
	userScope := scopes.ScopeRead | scopes.ScopeCreate | scopes.ScopeIndex | scopes.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK, crypt.TokenDomain)
	failOnError("NewMessageAuthenticator errored %v", err, t)

	tokenFirst, err := CreateUserForTests(m, userIDFirst, userScope)
	failOnError("SerializeAccessToken failed", err, t)
	tokenSecond, err := CreateUserForTests(m, userIDSecond, userScope)
	failOnError("SerializeAccessToken failed", err, t)

	firstTokenParts := strings.Split(tokenFirst, ".")
	secondTokenParts := strings.Split(tokenSecond, ".")

	au := &AuthnService{
		UserAuthenticator: &authn.UserAuthenticator{Authenticator: m},
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
		ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/enc.Encryptonize/Store")
		ctx = metadata.NewIncomingContext(ctx, md)
		_, err = au.CheckAccessToken(ctx)
		failOnSuccess("Auth should have errored", err, t)
	}
}

// Tests that accesstoken of wrong type gets rejected
func TestCheckAccessTokenInvalidAT(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	userScope := scopes.ScopeRead | scopes.ScopeCreate | scopes.ScopeIndex | scopes.ScopeObjectPermissions
	ASK, _ := crypt.Random(32)

	m, err := crypt.NewMessageAuthenticator(ASK, crypt.TokenDomain)
	failOnError("NewMessageAuthenticator errored", err, t)

	token, err := CreateUserForTests(m, userID, userScope)
	failOnError("SerializeAccessToken errored", err, t)

	token = "notBearer" + token[6:]
	var md = metadata.Pairs("authorization", token)
	au := &AuthnService{
		UserAuthenticator: &authn.UserAuthenticator{Authenticator: m},
	}

	ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, "/enc.Encryptonize/Store")
	ctx = metadata.NewIncomingContext(ctx, md)
	_, err = au.CheckAccessToken(ctx)
	failOnSuccess("Auth should have failed", err, t)
}

// Tests that accesstoken thats not hex gets rejected
func TestCheckAccessTokenInvalidATformat(t *testing.T) {
	au := &AuthnService{
		UserAuthenticator: &authn.UserAuthenticator{},
	}

	// Test wrong format AT
	// User credentials
	AT := "bearer thisIsANonHexaDecimalSentenceThatsAtLeastSixtyFourCharactersLong"
	var md = metadata.Pairs("authorization", AT)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, "/enc.Encryptonize/Store")
	_, err := au.CheckAccessToken(ctx)
	failOnSuccess("Invalid Auth Passed", err, t)

	if errStatus, _ := status.FromError(err); codes.InvalidArgument != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.InvalidArgument, errStatus.Code())
	}
}

// This test tries to access each endpoint with every but the required scope
// all tests should fail
func TestCheckAccessTokenNegativeScopes(t *testing.T) {
	ASK, _ := crypt.Random(32)
	m, err := crypt.NewMessageAuthenticator(ASK, crypt.TokenDomain)
	failOnError("Error creating MessageAuthenticator", err, t)

	au := &AuthnService{
		UserAuthenticator: &authn.UserAuthenticator{Authenticator: m},
	}

	for endpoint, rscope := range methodScopeMap {
		if rscope == scopes.ScopeNone {
			// endpoints that only require logged in users are already covered
			// by tests that check if authentication works
			continue
		}
		tscopes := (scopes.ScopeEnd - 1) &^ rscope
		tuid := uuid.Must(uuid.NewV4())
		token, err := CreateUserForTests(m, tuid, tscopes)
		failOnError("Error Creating User", err, t)

		var md = metadata.Pairs("authorization", token)

		ctx := context.WithValue(context.Background(), contextkeys.MethodNameCtxKey, endpoint)
		ctx = metadata.NewIncomingContext(ctx, md)
		_, err = au.CheckAccessToken(ctx)
		if err == nil {
			t.Errorf("User allowed to call endpoint %v requireing scopes %v using scopes %v", endpoint, rscope, tscopes)
		}
	}
}
