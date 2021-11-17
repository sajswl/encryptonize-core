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

// MemoryAuthStore is used to run a persistent AuthStorage mapped to a local file
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
	Tx           *bolt.Tx
	UserBucket   []byte
	ObjectBucket []byte
}

func (store *MemoryAuthStore) NewTransaction(ctx context.Context) (interfaces.AuthStoreTxInterface, error) {
	tx, err := store.db.Begin(true)
	if err != nil {
		return nil, err
	}

	return &MemoryAuthStoreTx{tx, store.userBucket, store.objectBucket}, nil
}

func (storeTx *MemoryAuthStoreTx) Commit(ctx context.Context) error {
	return storeTx.Tx.Commit()
}

func (storeTx *MemoryAuthStoreTx) Rollback(ctx context.Context) error {
	err := storeTx.Tx.Rollback()
	if errors.Is(err, bolt.ErrTxClosed) {
		return nil
	}
	return err
}

func (storeTx *MemoryAuthStoreTx) UserExists(ctx context.Context, userID uuid.UUID) (bool, error) {
	b := storeTx.Tx.Bucket(storeTx.UserBucket)

	user := b.Get(userID[:])
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
	b := storeTx.Tx.Bucket(storeTx.UserBucket)

	user := b.Get(userID[:])
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

	b := storeTx.Tx.Bucket(storeTx.UserBucket)

	return b.Put(protected.UserID[:], userBuffer.Bytes())
}

func (storeTx *MemoryAuthStoreTx) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	b := storeTx.Tx.Bucket(storeTx.UserBucket)

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
	b := storeTx.Tx.Bucket(storeTx.ObjectBucket)

	obj := b.Get(objectID[:])
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

	b := storeTx.Tx.Bucket(storeTx.ObjectBucket)

	return b.Put(protected.ObjectID[:], objectBuffer.Bytes())
}

func (storeTx *MemoryAuthStoreTx) UpdateAccessObject(ctx context.Context, accessObject common.ProtectedAccessObject) error {
	return storeTx.InsertAcccessObject(ctx, accessObject)
}

func (storeTx *MemoryAuthStoreTx) DeleteAccessObject(ctx context.Context, objectID uuid.UUID) error {
	b := storeTx.Tx.Bucket(storeTx.ObjectBucket)

	return b.Delete(objectID[:])
}
