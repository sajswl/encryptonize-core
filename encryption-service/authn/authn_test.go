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
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gofrs/uuid"

	"encryption-service/authstorage"
	"encryption-service/crypt"
)

var (
	ASK, _         = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	userID         = uuid.Must(uuid.FromString("00000000-0000-4000-8000-000000000002"))
	accessToken, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002")
	userScope      = ScopeUserManagement

	messageAuthenticator, _ = crypt.NewMessageAuthenticator(ASK)
	authenticator           = &Authenticator{
		MessageAuthenticator: messageAuthenticator,
	}

	expectedMessage, _ = hex.DecodeString("00000000000040008000000000000002" + "0000000000000000000000000000000000000000000000000000000000000002" + "1000000000000000")
	expectedTag, _     = messageAuthenticator.Tag(crypt.UsersDomain, expectedMessage)
)

func TestFormat(t *testing.T) {
	got, err := formatMessage(userID, accessToken, userScope)
	if err != nil {
		t.Fatalf("formatMessage errored: %v", err)
	}

	if !hmac.Equal(expectedMessage, got) {
		t.Errorf("Message doesn't match:\n%x\n%x", expectedMessage, got)
	}

	t.Logf("dev user tag: %x", expectedTag)
}

func TestFormatBadAccessToken(t *testing.T) {
	accessToken := []byte("wrong length")

	got, err := formatMessage(userID, accessToken, userScope)
	if (err == nil && err.Error() != "Invalid accessToken length") || got != nil {
		t.Errorf("formatMessage should have errored")
	}
}

func TestFormatBaduserScope(t *testing.T) {
	userScope := ScopeType(0xff)

	got, err := formatMessage(userID, accessToken, userScope)
	if (err == nil && err.Error() != "Invalid user type") || got != nil {
		t.Errorf("formatMessage should have errored")
	}
}

func TestFormatBadUserID(t *testing.T) {
	userID := uuid.Nil

	got, err := formatMessage(userID, accessToken, userScope)
	if (err == nil && err.Error() != "Invalid userID UUID") || got != nil {
		t.Errorf("formatMessage should have errored")
	}
}

func TestTag(t *testing.T) {
	got, err := authenticator.tag(userID, accessToken, userScope)
	if err != nil {
		t.Fatalf("tag errored: %v", err)
	}

	if !hmac.Equal(expectedTag, got) {
		t.Errorf("tag doesn't match:\n%x\n%x", expectedTag, got)
	}
}

func TestSignBadFormatMessage(t *testing.T) {
	userID := uuid.Nil

	got, err := authenticator.tag(userID, accessToken, userScope)
	if (err == nil && err.Error() != "Invalid userID UUID") || got != nil {
		t.Errorf("sign should have errored")
	}
}

func TestVerify(t *testing.T) {
	valid, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if !valid {
		t.Errorf("Verify should have returned valid")
	}
}

func TestVerifyBadFormatMessage(t *testing.T) {
	userID := uuid.Nil

	got, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if (err == nil && err.Error() != "Invalid userID UUID") || got != false {
		t.Errorf("verify should have errored")
	}
}

func TestVerifyModifiedUserID(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())

	valid, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifiedAccessToken(t *testing.T) {
	accessToken := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB")

	valid, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifieduserScope(t *testing.T) {
	userScope := ScopeRead | ScopeCreate | ScopeIndex | ScopeObjectPermissions

	valid, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifiedTag(t *testing.T) {
	expectedTag := append(expectedTag, 0)

	valid, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifiedASK(t *testing.T) {
	ma, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	authenticator := &Authenticator{
		MessageAuthenticator: ma,
	}

	valid, err := authenticator.verify(userID, accessToken, userScope, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestLoginUser(t *testing.T) {
	DBMock := &authstorage.AuthStoreMock{
		GetUserTagFunc: func(ctx context.Context, userID uuid.UUID) ([]byte, error) { return expectedTag, nil },
	}
	authenticator.AuthStore = DBMock
	ctx := context.Background()

	authenticated, err := authenticator.LoginUser(ctx, userID, accessToken, userScope)
	if err != nil || !authenticated {
		t.Fatalf("User not authenticated: %v", err)
	}
}

func TestLoginUserWrongTag(t *testing.T) {
	badTag, err := hex.DecodeString("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		t.Fatalf("Couldn't decode tag: %v", err)
	}
	DBMock := &authstorage.AuthStoreMock{
		GetUserTagFunc: func(ctx context.Context, userID uuid.UUID) ([]byte, error) { return badTag, nil },
	}
	authenticator.AuthStore = DBMock
	ctx := context.Background()

	authenticated, err := authenticator.LoginUser(ctx, userID, accessToken, userScope)
	if authenticated {
		t.Fatalf("User unlawfully authenticated: %v, %v", err, authenticated)
	}
}

func TestLoginUserFailedTagVerification(t *testing.T) {
	DBMock := &authstorage.AuthStoreMock{
		GetUserTagFunc: func(ctx context.Context, userID uuid.UUID) ([]byte, error) {
			return expectedTag, errors.New("failed verify")
		},
	}
	authenticator.AuthStore = DBMock
	ctx := context.Background()

	authenticated, err := authenticator.LoginUser(ctx, userID, accessToken, userScope)
	if authenticated {
		t.Fatalf("User unlawfully authenticated: %v, %v", err, authenticated)
	}
	expectedError := "failed verify"
	if err.Error() != expectedError {
		t.Fatalf("Didn't get expected error, got: %v expected %v", err, expectedError)
	}
}

func TestCreateOrUpdateUser(t *testing.T) {
	DBMock := &authstorage.AuthStoreMock{
		UpsertUserFunc: func(ctx context.Context, userID uuid.UUID, tag []byte) error { return nil },
	}
	authenticator.AuthStore = DBMock
	ctx := context.Background()

	err := authenticator.CreateOrUpdateUser(ctx, userID, accessToken, userScope)
	if err != nil {
		t.Fatalf("Failed to create/update user: %v", err)
	}
}

func TestCreateOrUpdateUserFail(t *testing.T) {
	DBMock := &authstorage.AuthStoreMock{
		UpsertUserFunc: func(ctx context.Context, userID uuid.UUID, tag []byte) error {
			return errors.New("upsert failed")
		},
	}
	authenticator.AuthStore = DBMock
	ctx := context.Background()

	err := authenticator.CreateOrUpdateUser(ctx, userID, accessToken, userScope)
	expectedError := "upsert failed"
	if err.Error() != expectedError {
		t.Fatalf("Didn't get expected error, got: %v expected %v", err, expectedError)
	}
}
