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

	"bytes"
	"context"
	"reflect"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"encryption-service/common"
	"encryption-service/contextkeys"
	"encryption-service/impl/crypt"
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
	FetchAccessObjectFunc func(ctx context.Context, objectID uuid.UUID) (*common.AccessObject, error)
}

func (a *AuthorizerMock) CreateAccessObject(_ context.Context, _, _ uuid.UUID, _ []byte) error {
	return nil
}

func (a *AuthorizerMock) FetchAccessObject(ctx context.Context, objectID uuid.UUID) (*common.AccessObject, error) {
	return a.FetchAccessObjectFunc(ctx, objectID)
}

func (a *AuthorizerMock) UpdateAccessObject(_ context.Context, _ uuid.UUID, _ common.AccessObject) error {
	return nil
}

func (a *AuthorizerMock) DeleteAccessObject(_ context.Context, _ uuid.UUID) error {
	return nil
}

func TestAuthorizeWrapper(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	objectID := uuid.Must(uuid.NewV4())
	Woek, err := crypt.Random(32)
	failOnError("Couldn't generate WOEK!", err, t)

	accessObject := &common.AccessObject{
		UserIDs: map[uuid.UUID]bool{
			userID: true,
		},
		Woek:    Woek,
		Version: 0,
	}

	authorizerMock := &AuthorizerMock{
		FetchAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) (*common.AccessObject, error) {
			return accessObject, nil
		},
	}
	authz := Authz{
		Authorizer: authorizerMock,
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)
	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectID)
	ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, "fake method")

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		accessObjectFetched, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(*common.AccessObject)
		if !ok {
			t.Fatal("Access object not added to context")
		}

		usersFetched := accessObjectFetched.GetUsers()
		woekFetched := accessObjectFetched.GetWOEK()

		if len(accessObject.UserIDs) != len(usersFetched) {
			t.Fatal("Access object in context not equal to original")
		}
		if !reflect.DeepEqual(accessObject.UserIDs, usersFetched) {
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

	unAuthAccessObject := &common.AccessObject{
		UserIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
		Woek:    Woek,
		Version: 0,
	}

	authorizerMock := &AuthorizerMock{
		FetchAccessObjectFunc: func(ctx context.Context, objectID uuid.UUID) (*common.AccessObject, error) {
			return unAuthAccessObject, nil
		},
	}
	authz := Authz{
		Authorizer: authorizerMock,
	}

	ctx := context.WithValue(context.Background(), contextkeys.UserIDCtxKey, userID)
	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authnStorageTxMock)
	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectID)
	ctx = context.WithValue(ctx, contextkeys.MethodNameCtxKey, "fake method")

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
