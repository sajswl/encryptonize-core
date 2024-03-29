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
package authstorage

import (
	"context"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/interfaces"
)

// TODO: we haven't found a better way to export testing structs yet

type AuthStoreMock struct {
	NewTransactionFunc func(ctx context.Context) (authStoreTx interfaces.AuthStoreTxInterface, err error)
	CloseFunc          func()
}

func (as *AuthStoreMock) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	return as.NewTransactionFunc(ctx)
}

func (as *AuthStoreMock) Close() {
	as.CloseFunc()
}

// AuthStoreTxMock allows to mock Auth Storage for testing
type AuthStoreTxMock struct {
	CommitFunc   func(ctx context.Context) error
	RollbackFunc func(ctx context.Context) error

	InsertUserFunc  func(ctx context.Context, protected *common.ProtectedUserData) error
	UpdateUserFunc  func(ctx context.Context, protected *common.ProtectedUserData) error
	GetUserDataFunc func(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error)
	RemoveUserFunc  func(ctx context.Context, userID uuid.UUID) error

	GroupExistsFunc       func(ctx context.Context, groupID uuid.UUID) (bool, error)
	InsertGroupFunc       func(ctx context.Context, group *common.ProtectedGroupData) error
	GetGroupDataBatchFunc func(ctx context.Context, groupIDs []uuid.UUID) ([]common.ProtectedGroupData, error)

	GetAccessObjectFunc     func(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error)
	InsertAcccessObjectFunc func(ctx context.Context, protected *common.ProtectedAccessObject) error
	UpdateAccessObjectFunc  func(ctx context.Context, protected *common.ProtectedAccessObject) error
	DeleteAccessObjectFunc  func(ctx context.Context, objectID uuid.UUID) error
}

func (db *AuthStoreTxMock) Commit(ctx context.Context) error {
	return db.CommitFunc(ctx)
}
func (db *AuthStoreTxMock) Rollback(ctx context.Context) error {
	return db.RollbackFunc(ctx)
}

func (db *AuthStoreTxMock) InsertUser(ctx context.Context, protected *common.ProtectedUserData) error {
	return db.InsertUserFunc(ctx, protected)
}

func (db *AuthStoreTxMock) UpdateUser(ctx context.Context, protected *common.ProtectedUserData) error {
	return db.UpdateUserFunc(ctx, protected)
}

func (db *AuthStoreTxMock) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	return db.RemoveUserFunc(ctx, userID)
}

func (db *AuthStoreTxMock) GetUserData(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
	return db.GetUserDataFunc(ctx, userID)
}

func (db *AuthStoreTxMock) GroupExists(ctx context.Context, groupID uuid.UUID) (bool, error) {
	return db.GroupExistsFunc(ctx, groupID)
}

func (db *AuthStoreTxMock) InsertGroup(ctx context.Context, protected *common.ProtectedGroupData) error {
	return db.InsertGroupFunc(ctx, protected)
}

func (db *AuthStoreTxMock) GetGroupDataBatch(ctx context.Context, groupIDs []uuid.UUID) ([]common.ProtectedGroupData, error) {
	return db.GetGroupDataBatchFunc(ctx, groupIDs)
}

func (db *AuthStoreTxMock) GetAccessObject(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
	return db.GetAccessObjectFunc(ctx, objectID)
}

func (db *AuthStoreTxMock) InsertAcccessObject(ctx context.Context, protected *common.ProtectedAccessObject) error {
	return db.InsertAcccessObjectFunc(ctx, protected)
}

func (db *AuthStoreTxMock) UpdateAccessObject(ctx context.Context, protected *common.ProtectedAccessObject) error {
	return db.UpdateAccessObjectFunc(ctx, protected)
}

func (db *AuthStoreTxMock) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) error {
	return db.DeleteAccessObjectFunc(ctx, objectID)
}
