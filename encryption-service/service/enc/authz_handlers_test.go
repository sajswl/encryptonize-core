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
package enc

import (
	"context"
	"testing"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"encryption-service/service/authn"
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
	authenticator := &authn.AuthnService{
		MessageAuthenticator: m,
	}

	accessToken := &authn.AccessToken{
		UserID:     userID,
		UserScopes: scopes,
	}

	token, err := authenticator.SerializeAccessToken(accessToken)
	if err != nil {
		return "", err
	}

	token = "bearer " + token
	return token, nil
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

	authnStorageTxMock := &authstorage.AuthStoreTxMock{
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
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

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

	authnStorageTxMock := &authstorage.AuthStoreTxMock{
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
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)

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
