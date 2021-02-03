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
	"sync"

	"github.com/gofrs/uuid"

	"encryption-service/interfaces"
)

// TODO: we haven't found a better way to export testing structs yet

// AuthStoreTxMock allows to mock Auth Storage for testing
type AuthStoreTxMock struct {
	CommitFunc   func(ctx context.Context) error
	RollbackFunc func(ctx context.Context) error

	GetUserTagFunc func(ctx context.Context, userID uuid.UUID) ([]byte, error)
	UpsertUserFunc func(ctx context.Context, userID uuid.UUID, tag []byte) error

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

func (db *AuthStoreTxMock) GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	return db.GetUserTagFunc(ctx, userID)
}
func (db *AuthStoreTxMock) UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error {
	return db.UpsertUserFunc(ctx, userID, tag)
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
	data sync.Map // 	map[uuid.UUID][][]byte
}

func NewMemoryAuthStore() *MemoryAuthStore {
	return &MemoryAuthStore{
		data: sync.Map{},
	}
}

func (store *MemoryAuthStore) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	return &MemoryAuthStoreTx{data: &store.data}, nil
}

func (store *MemoryAuthStore) Close() {}

type MemoryAuthStoreTx struct {
	data *sync.Map
}

func (m *MemoryAuthStoreTx) Commit(ctx context.Context) error {
	return nil
}
func (m *MemoryAuthStoreTx) Rollback(ctx context.Context) error {
	return nil
}

func (m *MemoryAuthStoreTx) GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	t, ok := m.data.Load(userID)
	if !ok {
		return nil, ErrNoRows
	}

	tag := make([]byte, len(t.([][]byte)[1]))
	copy(tag, t.([][]byte)[1])

	return tag, nil
}

func (m *MemoryAuthStoreTx) UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error {
	tagCopy := make([]byte, len(tag))
	copy(tagCopy, tag)
	m.data.Store(userID, [][]byte{nil, tagCopy})
	return nil
}

func (m *MemoryAuthStoreTx) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	t, ok := m.data.Load(objectID)
	if !ok {
		return nil, nil, ErrNoRows
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

	m.data.Store(objectID, [][]byte{dataCopy, tagCopy})
	return nil
}

func (m *MemoryAuthStoreTx) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	return m.InsertAcccessObject(ctx, objectID, data, tag)
}
