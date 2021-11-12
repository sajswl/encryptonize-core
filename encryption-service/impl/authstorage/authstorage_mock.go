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
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"time"

	"github.com/gofrs/uuid"
	bolt "go.etcd.io/bbolt"

	"encryption-service/common"
	"encryption-service/interfaces"
)

// TODO: we haven't found a better way to export testing structs yet

// AuthStoreTxMock allows to mock Auth Storage for testing
type AuthStoreTxMock struct {
	CommitFunc   func(ctx context.Context) error
	RollbackFunc func(ctx context.Context) error

	UserExistsFunc  func(ctx context.Context, userID uuid.UUID) (bool, error)
	InsertUserFunc  func(ctx context.Context, protected common.ProtectedUserData) error
	GetUserDataFunc func(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error)
	RemoveUserFunc  func(ctx context.Context, userID uuid.UUID) error

	GetAccessObjectFunc     func(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error)
	InsertAcccessObjectFunc func(ctx context.Context, protected common.ProtectedAccessObject) error
	UpdateAccessObjectFunc  func(ctx context.Context, protected common.ProtectedAccessObject) error
	DeleteAccessObjectFunc  func(ctx context.Context, objectID uuid.UUID) error
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
func (db *AuthStoreTxMock) InsertUser(ctx context.Context, protected common.ProtectedUserData) error {
	return db.InsertUserFunc(ctx, protected)
}

func (db *AuthStoreTxMock) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	return db.RemoveUserFunc(ctx, userID)
}

func (db *AuthStoreTxMock) GetUserData(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
	return db.GetUserDataFunc(ctx, userID)
}

func (db *AuthStoreTxMock) GetAccessObject(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
	return db.GetAccessObjectFunc(ctx, objectID)
}

func (db *AuthStoreTxMock) InsertAcccessObject(ctx context.Context, protected common.ProtectedAccessObject) error {
	return db.InsertAcccessObjectFunc(ctx, protected)
}

func (db *AuthStoreTxMock) UpdateAccessObject(ctx context.Context, protected common.ProtectedAccessObject) error {
	return db.UpdateAccessObjectFunc(ctx, protected)
}

func (db *AuthStoreTxMock) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) error {
	return db.DeleteAccessObjectFunc(ctx, objectID)
}

// MemoryAuthStoreTx is used by tests to mock the AutnStore in memory
type MemoryAuthStore struct {
	db           *bolt.DB
	userBucket   []byte
	objectBucket []byte
}

func NewMemoryAuthStore(dbFilePath string) (*MemoryAuthStore, error) {
	db, err := bolt.Open(dbFilePath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	userBucket := []byte("user")
	objectBucket := []byte("object")

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(userBucket)
		if err != nil {
			return err
		}
		_, err = tx.CreateBucketIfNotExists(objectBucket)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &MemoryAuthStore{db, userBucket, objectBucket}, nil
}

func (store *MemoryAuthStore) Close() {
	store.db.Close()
}

type MemoryAuthStoreTx struct {
	tx           *bolt.Tx
	userBucket   []byte
	objectBucket []byte
}

func (store *MemoryAuthStore) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	tx, err := store.db.Begin(true)
	if err != nil {
		return nil, err
	}

	return &MemoryAuthStoreTx{tx, store.userBucket, store.objectBucket}, nil
}

func (storeTx *MemoryAuthStoreTx) Commit(ctx context.Context) error {
	return storeTx.tx.Commit()
}

func (storeTx *MemoryAuthStoreTx) Rollback(ctx context.Context) error {
	err := storeTx.tx.Rollback()
	if errors.Is(err, bolt.ErrTxClosed) {
		return nil
	}
	return err
}

func (storeTx *MemoryAuthStoreTx) UserExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	b := storeTx.tx.Bucket(storeTx.userBucket)

	user := b.Get(userID[:])
	if err := storeTx.tx.Commit(); err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}

	userData := &common.ProtectedUserData{}
	dec := gob.NewDecoder(bytes.NewReader(user))
	err := dec.Decode(userData)
	if err != nil {
		return false, err
	}

	if userData.DeletedAt != nil {
		return false, nil
	}

	return true, nil
}

func (storeTx *MemoryAuthStoreTx) GetUserData(ctx context.Context, userID uuid.UUID) (*common.ProtectedUserData, error) {
	b := storeTx.tx.Bucket(storeTx.userBucket)

	user := b.Get(userID[:])
	if err := storeTx.tx.Commit(); err != nil {
		return nil, err
	}
	if user == nil {
		return nil, interfaces.ErrNotFound
	}

	userData := &common.ProtectedUserData{}
	dec := gob.NewDecoder(bytes.NewReader(user))
	err := dec.Decode(userData)
	if err != nil {
		return nil, err
	}

	if userData.DeletedAt != nil {
		return nil, interfaces.ErrNotFound
	}

	return userData, nil
}

func (storeTx *MemoryAuthStoreTx) InsertUser(ctx context.Context, protected common.ProtectedUserData) error {
	var userBuffer bytes.Buffer
	enc := gob.NewEncoder(&userBuffer)
	err := enc.Encode(protected)
	if err != nil {
		return err
	}

	b := storeTx.tx.Bucket(storeTx.userBucket)

	return b.Put(protected.UserID[:], userBuffer.Bytes())
}

func (storeTx *MemoryAuthStoreTx) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	b := storeTx.tx.Bucket(storeTx.userBucket)

	user := b.Get(userID[:])
	if user == nil {
		return interfaces.ErrNotFound
	}

	userData := &common.ProtectedUserData{}
	dec := gob.NewDecoder(bytes.NewReader(user))
	err := dec.Decode(userData)
	if err != nil {
		return err
	}

	if userData.DeletedAt != nil {
		return interfaces.ErrNotFound
	}

	currentTime := time.Now()
	userData.DeletedAt = &currentTime

	var userBuffer bytes.Buffer
	enc := gob.NewEncoder(&userBuffer)
	err = enc.Encode(userData)
	if err != nil {
		return err
	}

	return b.Put(userID[:], userBuffer.Bytes())
}

func (storeTx *MemoryAuthStoreTx) GetAccessObject(ctx context.Context, objectID uuid.UUID) (*common.ProtectedAccessObject, error) {
	b := storeTx.tx.Bucket(storeTx.objectBucket)

	obj := b.Get(objectID[:])
	if err := storeTx.tx.Commit(); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, interfaces.ErrNotFound
	}

	accessObject := &common.ProtectedAccessObject{}
	dec := gob.NewDecoder(bytes.NewReader(obj))
	err := dec.Decode(accessObject)
	if err != nil {
		return nil, err
	}

	return accessObject, nil
}

func (storeTx *MemoryAuthStoreTx) InsertAcccessObject(ctx context.Context, protected common.ProtectedAccessObject) error {
	var objectBuffer bytes.Buffer
	enc := gob.NewEncoder(&objectBuffer)
	err := enc.Encode(protected)
	if err != nil {
		return err
	}

	b := storeTx.tx.Bucket(storeTx.objectBucket)

	return b.Put(protected.ObjectID[:], objectBuffer.Bytes())
}

func (storeTx *MemoryAuthStoreTx) UpdateAccessObject(ctx context.Context, accessObject common.ProtectedAccessObject) error {
	return storeTx.InsertAcccessObject(ctx, accessObject)
}

func (storeTx *MemoryAuthStoreTx) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) error {
	b := storeTx.tx.Bucket(storeTx.objectBucket)

	return b.Delete(objectID[:])
}
