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
	"context"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/interfaces"
)

type UserAuthenticatorMock struct {
	NewUserFunc           func(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, string, error)
	UpdateUserFunc        func(ctx context.Context, userID uuid.UUID, userData *common.UserData) error
	RemoveUserFunc        func(ctx context.Context, userID uuid.UUID) error
	GetUserDataFunc       func(ctx context.Context, userID uuid.UUID) (*common.UserData, error)
	LoginUserFunc         func(ctx context.Context, userID uuid.UUID, password string) (string, error)
	ParseAccessTokenFunc  func(token string) (interfaces.AccessTokenInterface, error)
	NewGroupFunc          func(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, error)
	GetGroupDataBatchFunc func(ctx context.Context, groupIDs []uuid.UUID) ([]common.GroupData, error)
}

func (ua *UserAuthenticatorMock) NewUser(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, string, error) {
	return ua.NewUserFunc(ctx, scopes)
}

func (ua *UserAuthenticatorMock) UpdateUser(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
	return ua.UpdateUserFunc(ctx, userID, userData)
}

func (ua *UserAuthenticatorMock) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	return ua.RemoveUserFunc(ctx, userID)
}

func (ua *UserAuthenticatorMock) GetUserData(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
	return ua.GetUserDataFunc(ctx, userID)
}

func (ua *UserAuthenticatorMock) LoginUser(ctx context.Context, userID uuid.UUID, password string) (string, error) {
	return ua.LoginUserFunc(ctx, userID, password)
}

func (ua *UserAuthenticatorMock) ParseAccessToken(token string) (interfaces.AccessTokenInterface, error) {
	return ua.ParseAccessTokenFunc(token)
}

func (ua *UserAuthenticatorMock) NewGroup(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, error) {
	return ua.NewGroupFunc(ctx, scopes)
}

func (ua *UserAuthenticatorMock) GetGroupDataBatch(ctx context.Context, groupIDs []uuid.UUID) ([]common.GroupData, error) {
	return ua.GetGroupDataBatchFunc(ctx, groupIDs)
}
