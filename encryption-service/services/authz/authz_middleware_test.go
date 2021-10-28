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
	"bytes"
	"context"
	"testing"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/impl/authstorage"
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
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

func TestAuthorizeWrapper(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	Woek, err := crypt.Random(32)
	failOnError("Couldn't generate WOEK!", err, t)

	accessObject := &authzimpl.AccessObject{
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

	messageAuthenticator, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), crypt.AccessObjectsDomain)
	failOnError("NewMessageAuthenticator errored", err, t)
	aoAuth := &authzimpl.Authorizer{AccessObjectMAC: messageAuthenticator}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)
	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectID)
	ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, "fake method")

	authz := Authz{
		Authorizer: aoAuth,
	}

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		accessObjectFetched, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(interfaces.AccessObjectInterface)
		if !ok {
			t.Fatal("Access object not added to context")
		}

		usersFetched, err := accessObjectFetched.GetUsers()
		failOnError("Could not get users", err, t)

		woekFetched := accessObjectFetched.GetWOEK()

		if len(accessObject.UserIds) != len(usersFetched) {
			t.Fatal("Access object in context not equal to original")
		}
		if !bytes.Equal(accessObject.UserIds[0], usersFetched[0].Bytes()) {
			t.Fatal("Access object in context not equal to original")
		}
		if !bytes.Equal(accessObject.Woek, woekFetched) {
			t.Fatal("Access object in context not equal to original")
		}

		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	if err != nil {
		t.Fatalf("User couldn't be authorized")
	}
}

func TestAuthorizeWrapperUnauthorized(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	Woek, err := crypt.Random(32)
	failOnError("Couldn't generate WOEK!", err, t)

	unAuthAccessObject := &authzimpl.AccessObject{
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

	messageAuthenticator, err := crypt.NewMessageAuthenticator([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), crypt.AccessObjectsDomain)
	failOnError("NewMessageAuthenticator errored", err, t)
	aoAuth := &authzimpl.Authorizer{AccessObjectMAC: messageAuthenticator}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)
	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectID)
	ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, "fake method")

	authz := Authz{
		Authorizer: aoAuth,
	}

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
