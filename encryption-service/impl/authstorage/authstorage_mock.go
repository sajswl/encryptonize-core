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
package authstorage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/gofrs/uuid"

	"encryption-service/interfaces"
	"encryption-service/users"
)

// TODO: we haven't found a better way to export testing structs yet

// AuthStoreTxMock allows to mock Auth Storage for testing
type AuthStoreTxMock struct {
	CommitFunc   func(ctx context.Context) error
	RollbackFunc func(ctx context.Context) error

	UserExistsFunc  func(ctx context.Context, userID uuid.UUID) (bool, error)
	InsertUserFunc  func(ctx context.Context, user users.UserData) error
	GetUserDataFunc func(ctx context.Context, userID uuid.UUID) ([]byte, []byte, error)
	RemoveUserFunc  func(ctx context.Context, userID uuid.UUID) error

	GetAccessObjectFunc     func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error)
	InsertAcccessObjectFunc func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
	UpdateAccessObjectFunc  func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
}

func (db *AuthStoreTxMock) Commit(ctx context.Context) error {
	return db.CommitFunc(ctx)
}
func (db *AuthStoreTxMock) Rollback(ctx context.Context) error {
	return db.RollbackFunc(ctx)
}

func (db *AuthStoreTxMock) UserExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	return db.UserExistsFunc(ctx, userID)
}
func (db *AuthStoreTxMock) InsertUser(ctx context.Context, user users.UserData) error {
	return db.InsertUserFunc(ctx, user)
}

func (db *AuthStoreTxMock) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	return db.RemoveUserFunc(ctx, userID)
}

func (db *AuthStoreTxMock) GetUserData(ctx context.Context, userID uuid.UUID) (userData []byte, key []byte, err error) {
	return db.GetUserDataFunc(ctx, userID)
}

func (db *AuthStoreTxMock) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	return db.GetAccessObjectFunc(ctx, objectID)
}

func (db *AuthStoreTxMock) InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	return db.InsertAcccessObjectFunc(ctx, objectID, data, tag)
}

func (db *AuthStoreTxMock) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	return db.UpdateAccessObjectFunc(ctx, objectID, data, tag)
}

// MemoryAuthStoreTx is used by tests to mock the AutnStore in memory
type MemoryAuthStore struct {
	Data sync.Map // 	map[uuid.UUID][][]byte
}

func NewMemoryAuthStore() *MemoryAuthStore {
	return &MemoryAuthStore{
		Data: sync.Map{},
	}
}

func (store *MemoryAuthStore) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	return &MemoryAuthStoreTx{Data: &store.Data}, nil
}

func (store *MemoryAuthStore) Close() {}

type MemoryAuthStoreTx struct {
	Data *sync.Map
}

func (m *MemoryAuthStoreTx) Commit(ctx context.Context) error {
	return nil
}
func (m *MemoryAuthStoreTx) Rollback(ctx context.Context) error {
	return nil
}

func (m *MemoryAuthStoreTx) UserExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	_, ok := m.Data.Load(userID)
	if !ok {
		return false, nil
	}

	return true, nil
}

func (m *MemoryAuthStoreTx) GetUserData(ctx context.Context, userID uuid.UUID) (userData []byte, key []byte, err error) {
	user, ok := m.Data.Load(userID)
	if !ok {
		return nil, nil, interfaces.ErrNotFound
	}

	data, ok := user.(users.UserData)
	if !ok {
		return nil, nil, errors.New("unable to cast to UserData")
	}

	return data.ConfidentialUserData, data.WrappedKey, nil
}

func (m *MemoryAuthStoreTx) InsertUser(ctx context.Context, user users.UserData) error {
	// TODO: check if already contained
	m.Data.Store(user.UserID, user)
	return nil
}

func (m *MemoryAuthStoreTx) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	// TODO: unsafe for concurrent usage
	user, ok := m.Data.Load(userID)
	if !ok {
		return interfaces.ErrNotFound
	}

	userData, ok := user.(users.UserData)
	if !ok {
		return errors.New("unable to cast to UserData")
	}

	userData.DeletedAt = time.Now()
	m.Data.Store(userID, userData)
	return nil
}

func (m *MemoryAuthStoreTx) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	t, ok := m.Data.Load(objectID)
	if !ok {
		return nil, nil, interfaces.ErrNotFound
	}

	data := make([]byte, len(t.([][]byte)[0]))
	copy(data, t.([][]byte)[0])

	tag := make([]byte, len(t.([][]byte)[1]))
	copy(tag, t.([][]byte)[1])

	return data, tag, nil
}

func (m *MemoryAuthStoreTx) InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	tagCopy := make([]byte, len(tag))
	copy(tagCopy, tag)

	m.Data.Store(objectID, [][]byte{dataCopy, tagCopy})
	return nil
}

func (m *MemoryAuthStoreTx) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	return m.InsertAcccessObject(ctx, objectID, data, tag)
}
