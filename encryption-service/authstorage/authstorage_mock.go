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

	"github.com/gofrs/uuid"
)

// TODO: we haven't found a better way to export testing structs yet

// AuthStoreMock allows to mock Auth Storage for testing
type AuthStoreMock struct {
	CommitFunc   func(ctx context.Context) error
	RollbackFunc func(ctx context.Context) error

	GetUserTagFunc func(ctx context.Context, userID uuid.UUID) ([]byte, error)
	UpsertUserFunc func(ctx context.Context, userID uuid.UUID, tag []byte) error

	GetAccessObjectFunc     func(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error)
	InsertAcccessObjectFunc func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
	UpdateAccessObjectFunc  func(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
}

func (db *AuthStoreMock) Commit(ctx context.Context) error {
	return db.CommitFunc(ctx)
}
func (db *AuthStoreMock) Rollback(ctx context.Context) error {
	return db.RollbackFunc(ctx)
}

func (db *AuthStoreMock) GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	return db.GetUserTagFunc(ctx, userID)
}
func (db *AuthStoreMock) UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error {
	return db.UpsertUserFunc(ctx, userID, tag)
}

func (db *AuthStoreMock) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	return db.GetAccessObjectFunc(ctx, objectID)
}

func (db *AuthStoreMock) InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	return db.InsertAcccessObjectFunc(ctx, objectID, data, tag)
}

func (db *AuthStoreMock) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	return db.UpdateAccessObjectFunc(ctx, objectID, data, tag)
}

// MemoryAuthStore is used by tests to mock the AutnStore in memory
type MemoryAuthStore struct {
	Data map[uuid.UUID][][]byte
}

func NewMemoryAuthStore() *MemoryAuthStore {
	return &MemoryAuthStore{
		Data: make(map[uuid.UUID][][]byte),
	}
}

func (m *MemoryAuthStore) Commit(ctx context.Context) error {
	return nil
}
func (m *MemoryAuthStore) Rollback(ctx context.Context) error {
	return nil
}

func (m *MemoryAuthStore) GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	t, ok := m.Data[userID]
	if !ok {
		return nil, ErrNoRows
	}

	return t[1], nil
}
func (m *MemoryAuthStore) UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error {
	m.Data[userID] = [][]byte{nil, tag}
	return nil
}

func (m *MemoryAuthStore) GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error) {
	t, ok := m.Data[objectID]
	if !ok {
		return nil, nil, ErrNoRows
	}

	return t[0], t[1], nil
}

func (m *MemoryAuthStore) InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	m.Data[objectID] = [][]byte{data, tag}
	return nil
}

func (m *MemoryAuthStore) UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error {
	m.Data[objectID] = [][]byte{data, tag}
	return nil
}
