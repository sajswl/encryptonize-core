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
package objectstorage

import (
	"context"
	"time"

	bolt "go.etcd.io/bbolt"

	"encryption-service/interfaces"
)

// MemoryObjectStore is used to run a persistent ObjectStore mapped to a local file
type MemoryObjectStore struct {
	db           *bolt.DB
	objectBucket []byte
}

func NewMemoryObjectStore(dbFilepath string) (*MemoryObjectStore, error) {
	db, err := bolt.Open(dbFilepath, 0600, &bolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		return nil, err
	}

	objectBucket := []byte("object")

	err = db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(objectBucket)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return &MemoryObjectStore{db, objectBucket}, nil
}

func (o *MemoryObjectStore) Store(ctx context.Context, objectID string, object []byte) error {
	return o.db.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(o.objectBucket)
		return b.Put([]byte(objectID), object)
	})
}

func (o *MemoryObjectStore) Retrieve(ctx context.Context, objectID string) (object []byte, err error) {
	object = nil

	err = o.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(o.objectBucket)

		obj := b.Get([]byte(objectID))
		if obj == nil {
			return interfaces.ErrNotFound
		}

		object = make([]byte, len(obj))
		copy(object, obj)

		return nil
	})

	return
}

func (o *MemoryObjectStore) Delete(ctx context.Context, objectID string) error {
	return o.db.Batch(func(tx *bolt.Tx) error {
		b := tx.Bucket(o.objectBucket)
		return b.Delete([]byte(objectID))
	})
}
