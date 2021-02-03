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
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/crypt"
)

var (
	ASK, _    = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	userID    = uuid.Must(uuid.FromString("00000000-0000-4000-8000-000000000002"))
	nonce, _  = hex.DecodeString("00000000000000000000000000000002")
	userScope = ScopeUserManagement
	AT        = &AccessToken{
		UserID:     userID,
		UserScopes: userScope,
	}

	messageAuthenticator, _ = crypt.NewMessageAuthenticator(ASK)
	authenticator           = &AuthnService{
		MessageAuthenticator: messageAuthenticator,
	}

	expectedSerialized = "ChAAAAAAAABAAIAAAAAAAAACEgEE"
	expectedMessage, _ = base64.RawURLEncoding.DecodeString(expectedSerialized)
	expectedTag, _     = messageAuthenticator.Tag(crypt.TokenDomain, append(nonce, expectedMessage...))
	expectedToken      = "ChAAAAAAAABAAIAAAAAAAAACEgEE.AAAAAAAAAAAAAAAAAAAAAg." + base64.RawURLEncoding.EncodeToString(expectedTag)
)

func TestSerialize(t *testing.T) {
	token, err := authenticator.SerializeAccessToken(AT)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}

	serialized := strings.Split(token, ".")[0]

	if serialized != expectedSerialized {
		t.Errorf("Message doesn't match:\n%v\n%v", expectedToken, token)
	}

	t.Logf("dev admin token: %v", expectedToken)
}

func TestSerializeParseIdentity(t *testing.T) {
	token, err := authenticator.SerializeAccessToken(AT)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}

	AT2, err := authenticator.ParseAccessToken(token)
	failOnError("Parsing serialized access token failed", err, t)
	if AT2.UserID != AT.UserID || AT2.UserScopes != AT.UserScopes {
		t.Errorf("Serialize parse identity violated")
	}
}

func TestSerializeBaduserScope(t *testing.T) {
	BadScopeAT := &AccessToken{
		UserID:     userID,
		UserScopes: ScopeType(0xff),
	}

	token, err := authenticator.SerializeAccessToken(BadScopeAT)
	if (err == nil && err.Error() != "Invalid scopes") || token != "" {
		t.Errorf("formatMessage should have errored")
	}
}

func TestSerializeBadUserID(t *testing.T) {
	BadUUIDAT := &AccessToken{
		UserID:     uuid.Nil,
		UserScopes: userScope,
	}

	token, err := authenticator.SerializeAccessToken(BadUUIDAT)
	if (err == nil && err.Error() != "Invalid userID UUID") || token != "" {
		t.Errorf("formatMessage should have errored")
	}
}

func TestParseAccessToken(t *testing.T) {
	AT, err := authenticator.ParseAccessToken(expectedToken)
	failOnError("ParseAccessToken did fail", err, t)

	if AT.UserID != userID || AT.UserScopes != userScope {
		t.Errorf("Parsed Access Token contained different data!")
	}
}

// the checks for the modified parts of the token is currently handled
// in auth_handlers_test (TestAuthMiddlewareSwappedTokenParts)

func TestVerifyModifiedASK(t *testing.T) {
	ma, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	failOnError("NewMessageAuthenticator errored", err, t)

	authenticator := &AuthnService{
		MessageAuthenticator: ma,
	}

	_, err = authenticator.ParseAccessToken(expectedToken)
	failOnSuccess("ParseAccessToken should have failed with modified ASK", err, t)
	if err.Error() != "invalid token" {
		t.Errorf("ParseAccessToken failed with different error. Expected \"invalid token\" but go %v", err)
	}
}

func TestSerializeAccessTokenAnyScopes(t *testing.T) {
	// try to create a use for every valid combination of scopes
	// even the empty set
	for i := uint64(0); i < uint64(ScopeEnd); i++ {
		uScope := ScopeType(i)
		tAT := &AccessToken{
			UserID:     userID,
			UserScopes: uScope,
		}
		_, err := authenticator.SerializeAccessToken(tAT)
		if err != nil {
			t.Fatalf("Failed to create/update user with scopes %v: %v", uScope, err)
		}
	}
}
