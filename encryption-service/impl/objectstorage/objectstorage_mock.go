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

import "context"

type ObjectStoreMock struct {
	StoreFunc    func(ctx context.Context, objectID string, object []byte) error
	RetrieveFunc func(ctx context.Context, objectID string) ([]byte, error)
	DeleteFunc   func(ctx context.Context, objectID string) error
}

func (o *ObjectStoreMock) Store(ctx context.Context, objectID string, object []byte) error {
	return o.StoreFunc(ctx, objectID, object)
}

func (o *ObjectStoreMock) Retrieve(ctx context.Context, objectID string) ([]byte, error) {
	return o.RetrieveFunc(ctx, objectID)
}

func (o *ObjectStoreMock) Delete(ctx context.Context, objectID string) error {
	return o.DeleteFunc(ctx, objectID)
}
