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

	"encryption-service/common"
	"encryption-service/impl/authn"
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
	accessObject *common.AccessObject
}

func (a *AuthorizerMock) CreateAccessObject(_ context.Context, _, _ uuid.UUID, _ []byte) error {
	return nil
}

func (a *AuthorizerMock) FetchAccessObject(ctx context.Context, objectID uuid.UUID) (*common.AccessObject, error) {
	if a.accessObject == nil {
		return nil, errors.New("No object")
	}
	return a.accessObject, nil
}

func (a *AuthorizerMock) UpdateAccessObject(_ context.Context, _ uuid.UUID, _ common.AccessObject) error {
	return nil
}

func (a *AuthorizerMock) DeleteAccessObject(_ context.Context, _ uuid.UUID) error {
	return nil
}

type MockData struct {
	methodName   string
	userID       uuid.UUID
	objectID     uuid.UUID
	accessObject *common.AccessObject
	userData     *common.UserData
	groupData    map[uuid.UUID]common.GroupData
}

func SetupMocks(mockData MockData) (context.Context, *Authz) {
	ctx := context.Background()

	if mockData.userID != uuid.Nil {
		ctx = context.WithValue(ctx, common.UserIDCtxKey, mockData.userID)
	}
	if mockData.objectID != uuid.Nil {
		ctx = context.WithValue(ctx, common.ObjectIDCtxKey, mockData.objectID)
	}
	if mockData.methodName != "" {
		ctx = context.WithValue(ctx, common.MethodNameCtxKey, mockData.methodName)
	}

	userAuthenticatorMock := &authn.UserAuthenticatorMock{
		GetUserDataFunc: func(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
			if mockData.userData == nil {
				return nil, errors.New("No data")
			}
			return mockData.userData, nil
		},
		GetGroupDataBatchFunc: func(ctx context.Context, groupIDs []uuid.UUID) ([]common.GroupData, error) {
			groupDataBatch := make([]common.GroupData, 0, len(groupIDs))
			for _, groupID := range groupIDs {
				groupData, ok := mockData.groupData[groupID]
				if !ok {
					return nil, errors.New("No data")
				}
				groupDataBatch = append(groupDataBatch, groupData)
			}
			return groupDataBatch, nil
		},
	}

	authz := &Authz{
		Authorizer:        &AuthorizerMock{accessObject: mockData.accessObject},
		UserAuthenticator: userAuthenticatorMock,
	}

	return ctx, authz
}

var mockData = MockData{
	methodName: "/storage.Encryptonize/Retrieve",
	userID:     uuid.Must(uuid.NewV4()),
	objectID:   uuid.Must(uuid.NewV4()),
	accessObject: &common.AccessObject{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	},
	userData: &common.UserData{
		GroupIDs: map[uuid.UUID]bool{
			userID: true,
		},
	},
	groupData: map[uuid.UUID]common.GroupData{
		userID: {Scopes: common.ScopeRead},
	},
}

func TestAuthzMiddleware(t *testing.T) {
	ctx, authz := SetupMocks(mockData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		accessObjectFetched, ok := ctx.Value(common.AccessObjectCtxKey).(*common.AccessObject)
		if !ok {
			t.Fatal("Access object not added to context")
		}

		if !reflect.DeepEqual(mockData.accessObject, accessObjectFetched) {
			t.Fatal("Access object in context not equal to original")
		}

		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnError("Expected user to be authorized", err, t)
}

func TestAuthzMiddlewareUnauthorized(t *testing.T) {
	mockData.userData = &common.UserData{
		GroupIDs: map[uuid.UUID]bool{
			uuid.Must(uuid.NewV4()): true,
		},
	}
	ctx, authz := SetupMocks(mockData)

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

func TestAuthzMiddlewareWrongScope(t *testing.T) {
	mockData.groupData = map[uuid.UUID]common.GroupData{
		userID: {Scopes: common.ScopeDelete},
	}
	ctx, authz := SetupMocks(mockData)

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
	mockData.accessObject = nil
	ctx, authz := SetupMocks(mockData)

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
	mockData.userData = nil
	ctx, authz := SetupMocks(mockData)

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

func TestAuthzNoGroupData(t *testing.T) {
	mockData.groupData = nil
	ctx, authz := SetupMocks(mockData)

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
	mockData.methodName = ""
	ctx, authz := SetupMocks(mockData)

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
	mockData.userID = uuid.Nil
	ctx, authz := SetupMocks(mockData)

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
	mockData.objectID = uuid.Nil
	ctx, authz := SetupMocks(mockData)

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
	mockData.methodName = "/app.Encryptonize/Version"
	ctx, authz := SetupMocks(mockData)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		_, ok := ctx.Value(common.AccessObjectCtxKey).(*common.AccessObject)
		if ok {
			t.Fatal("Found unexpected access object in context")
		}
		return nil, nil
	}

	_, err = authz.AuthorizationUnaryServerInterceptor()(ctx, nil, nil, handler)
	failOnError("Expected authorization to be skipped", err, t)
}
