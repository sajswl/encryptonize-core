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
	"errors"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/interfaces"
)

// TODO: we haven't found a better way to export testing structs yet

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

// MemoryAuthStoreTx is used by tests to mock the AutnStore in memory
type MemoryAuthStore struct {
	UserData   sync.Map // 	map[uuid.UUID][][]byte
	GroupData  sync.Map // 	map[uuid.UUID][][]byte
	AccessData sync.Map // 	map[uuid.UUID][][]byte
}

func NewMemoryAuthStore() *MemoryAuthStore {
	return &MemoryAuthStore{
		UserData:   sync.Map{},
		GroupData:  sync.Map{},
		AccessData: sync.Map{},
	}
}

func (store *MemoryAuthStore) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	return &MemoryAuthStoreTx{
		UserData:   &store.UserData,
		GroupData:  &store.GroupData,
		AccessData: &store.AccessData,
	}, nil
}

func (store *MemoryAuthStore) Close() {}

type MemoryAuthStoreTx struct {
	UserData   *sync.Map
	GroupData  *sync.Map
	AccessData *sync.Map
}

func (m *MemoryAuthStoreTx) Commit(ctx context.Context) error {
	return nil
}
func (m *MemoryAuthStoreTx) Rollback(ctx context.Context) error {
	return nil
}

func (m *MemoryAuthStoreTx) GetUserData(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
	user, ok := m.UserData.Load(userID)
	if !ok {
		return nil, interfaces.ErrNotFound
	}

	data, ok := user.(*common.ProtectedUserData)
	if !ok {
		return nil, errors.New("unable to cast to ProtectedUserData")
	}

	if data.DeletedAt != nil {
		return nil, interfaces.ErrNotFound
	}

	return data, nil
}

func (m *MemoryAuthStoreTx) InsertUser(ctx context.Context, user *common.ProtectedUserData) error {
	// TODO: check if already contained
	m.UserData.Store(user.UserID, user)
	return nil
}

func (m MemoryAuthStoreTx) UpdateUser(ctx context.Context, protected *common.ProtectedUserData) error {
	return m.InsertUser(ctx, protected)
}

func (m *MemoryAuthStoreTx) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	// TODO: unsafe for concurrent usage
	user, ok := m.UserData.Load(userID)
	if !ok {
		return interfaces.ErrNotFound
	}

	userData, ok := user.(*common.ProtectedUserData)
	if !ok {
		return errors.New("unable to cast to ProtectedUserData")
	}

	if userData.DeletedAt != nil {
		return interfaces.ErrNotFound
	}

	userData.DeletedAt = func() *time.Time { t := time.Now(); return &t }()

	m.UserData.Store(userID, userData)
	return nil
}

func (m *MemoryAuthStoreTx) GroupExists(ctx context.Context, groupID uuid.UUID) (bool, error) {
	group, ok := m.GroupData.Load(groupID)
	if !ok {
		return false, nil
	}

	_, ok = group.(*common.ProtectedGroupData)
	if !ok {
		return false, errors.New("unable to cast to ProtectedUserData")
	}

	return true, nil
}

func (m *MemoryAuthStoreTx) InsertGroup(ctx context.Context, protected *common.ProtectedGroupData) error {
	// TODO: check if already contained
	m.GroupData.Store(protected.GroupID, protected)
	return nil
}

func (m *MemoryAuthStoreTx) GetGroupDataBatch(ctx context.Context, groupIDs []uuid.UUID) ([]common.ProtectedGroupData, error) {
	protectedBatch := make([]common.ProtectedGroupData, 0, len(groupIDs))

	for _, groupID := range groupIDs {
		group, ok := m.GroupData.Load(groupID)
		if !ok {
			return nil, interfaces.ErrNotFound
		}

		protected, ok := group.(*common.ProtectedGroupData)
		if !ok {
			return nil, errors.New("unable to cast to UserData")
		}

		protectedBatch = append(protectedBatch, *protected)
	}

	return protectedBatch, nil
}

func (m *MemoryAuthStoreTx) GetAccessObject(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
	accessObject, ok := m.AccessData.Load(objectID)
	if !ok {
		return nil, interfaces.ErrNotFound
	}

	data, ok := accessObject.(*common.ProtectedAccessObject)
	if !ok {
		return nil, errors.New("unable to cast to ProtectedAccessObject")
	}

	return data, nil
}

func (m *MemoryAuthStoreTx) InsertAcccessObject(ctx context.Context, accessObject *common.ProtectedAccessObject) error {
	m.AccessData.Store(accessObject.ObjectID, accessObject)
	return nil
}

func (m *MemoryAuthStoreTx) UpdateAccessObject(ctx context.Context, accessObject *common.ProtectedAccessObject) error {
	return m.InsertAcccessObject(ctx, accessObject)
}

func (m *MemoryAuthStoreTx) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) error {
	m.AccessData.Delete(objectID)
	return nil
}
