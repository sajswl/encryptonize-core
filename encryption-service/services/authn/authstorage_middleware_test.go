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
	"testing"

	"context"
	"errors"
	"reflect"

	"github.com/gofrs/uuid"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"encryption-service/common"
	authnimpl "encryption-service/impl/authn"
	"encryption-service/impl/authstorage"
	"encryption-service/interfaces"
)

type MockData struct {
	methodName string
	userID     uuid.UUID
	authStore  *authstorage.AuthStoreMock
}

func SetupMocks(mockData MockData) (context.Context, *Authn) {
	ctx := context.Background()

	if mockData.userID != uuid.Nil {
		ctx = context.WithValue(ctx, common.UserIDCtxKey, mockData.userID)
	}
	if mockData.methodName != "" {
		ctx = context.WithValue(ctx, common.MethodNameCtxKey, mockData.methodName)
	}

	authn := &Authn{
		AuthStore:         mockData.authStore,
		UserAuthenticator: &authnimpl.UserAuthenticatorMock{},
	}

	return ctx, authn
}

func TestAuthStorage(t *testing.T) {
	authStoreTxMock := &authstorage.AuthStoreTxMock{
		RollbackFunc: func(ctx context.Context) (err error) {
			return nil
		},
	}

	mockData := MockData{
		methodName: "/storage.Encryptonize/Store",
		userID:     uuid.Must(uuid.NewV4()),
		authStore: &authstorage.AuthStoreMock{
			NewTransactionFunc: func(ctx context.Context) (authStoreTx interfaces.AuthStoreTxInterface, err error) {
				return authStoreTxMock, nil
			},
			CloseFunc: func() {},
		},
	}

	ctx, authn := SetupMocks(mockData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		authStorageTxExtracted, ok := ctx.Value(common.AuthStorageTxCtxKey).(*authstorage.AuthStoreTxMock)
		if !ok {
			t.Fatal("AuthStorage not added to context")
		}

		if !reflect.DeepEqual(authStoreTxMock, authStorageTxExtracted) {
			t.Fatal("AuthStorage in context not equal to original")
		}

		return nil, nil
	}

	_, err := authn.AuthStorageUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnError("Expected AuthStorage to have been added to context", err, t)
}

func TestAuthStorageNoMethod(t *testing.T) {
	mockData := MockData{
		methodName: "",
		userID:     uuid.Must(uuid.NewV4()),
		authStore:  &authstorage.AuthStoreMock{},
	}

	ctx, authn := SetupMocks(mockData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err := authn.AuthStorageUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("AuthStorage should not have been injected to context", err, t)

	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Fatalf("Wrong error returned: expected %v, but got %v", codes.Internal, errStatus)
	}
}

func TestAuthStorageNoNewTransaction(t *testing.T) {
	newTransactionCall := false

	mockData := MockData{
		methodName: "/storage.Encryptonize/Store",
		userID:     uuid.Must(uuid.NewV4()),
		authStore: &authstorage.AuthStoreMock{
			NewTransactionFunc: func(ctx context.Context) (authStoreTx interfaces.AuthStoreTxInterface, err error) {
				newTransactionCall = true
				return nil, errors.New("NewTransaction not implemented")
			},
			CloseFunc: func() {},
		},
	}

	ctx, authn := SetupMocks(mockData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		t.Fatal("Handler should not have been called")
		return nil, nil
	}

	_, err := authn.AuthStorageUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnSuccess("AuthStorage should not have been injected to context", err, t)

	if errStatus, _ := status.FromError(err); codes.Internal != errStatus.Code() {
		t.Errorf("Auth failed, but got incorrect error code, expected %v but got %v", codes.Internal, errStatus.Code())
	}

	if !newTransactionCall {
		t.Fatal("Failed to begin a transaction")
	}
}

func TestAuthStorageRollback(t *testing.T) {
	rollbackCall := false

	mockData := MockData{
		methodName: "/storage.Encryptonize/Store",
		userID:     uuid.Must(uuid.NewV4()),
		authStore: &authstorage.AuthStoreMock{
			NewTransactionFunc: func(ctx context.Context) (authStoreTx interfaces.AuthStoreTxInterface, err error) {
				authStoreTxMock := &authstorage.AuthStoreTxMock{
					RollbackFunc: func(ctx context.Context) (err error) {
						rollbackCall = true
						return errors.New("Rollback not implemented")
					},
				}
				return authStoreTxMock, nil
			},
			CloseFunc: func() {},
		},
	}

	ctx, authn := SetupMocks(mockData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, nil
	}

	_, err := authn.AuthStorageUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnError("Expected AuthStorage to have been added to context", err, t)

	if !rollbackCall {
		t.Fatal("Transaction failed to rollback")
	}
}
