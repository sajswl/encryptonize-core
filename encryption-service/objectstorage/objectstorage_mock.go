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
package objectstorage

import (
	"context"
	"errors"
)

// MemoryObjectStore is used by tests to mock the ObjectStore in memory
type MemoryObjectStore struct {
	Data map[string][]byte
}

func NewMemoryObjectStore() *MemoryObjectStore {
	return &MemoryObjectStore{
		Data: make(map[string][]byte),
	}
}

func (o *MemoryObjectStore) Store(ctx context.Context, objectID string, object []byte) error {
	o.Data[objectID] = object
	return nil
}

func (o *MemoryObjectStore) Retrieve(ctx context.Context, objectID string) ([]byte, error) {
	object, ok := o.Data[objectID]

	if !ok {
		return nil, errors.New("object not found")
	}
	return object, nil
}
