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
	"errors"
	"sync"
)

// MemoryObjectStore is used by tests to mock the ObjectStore in memory
type MemoryObjectStore struct {
	Data sync.Map // map[string][]byte
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{
		Data: sync.Map{},
	}
}

func (o *MemoryObjectStore) Store(ctx context.Context, objectID string, object []byte) error {
	objectCopy := make([]byte, len(object))
	copy(objectCopy, object)
	o.Data.Store(objectID, objectCopy)
	return nil
}

func (o *MemoryObjectStore) Retrieve(ctx context.Context, objectID string) ([]byte, error) {
	object, ok := o.Data.Load(objectID)

	if !ok {
		return nil, errors.New("object not found")
	}

	objectCopy := make([]byte, len(object.([]byte)))
	copy(objectCopy, object.([]byte))

	return objectCopy, nil
}
