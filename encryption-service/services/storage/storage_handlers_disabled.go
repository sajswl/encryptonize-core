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
package storage

import (
	"context"

	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

type DisabledStorage struct {
	UnimplementedEncryptonizeServer
}

func (strg *DisabledStorage) GetStorageServer() EncryptonizeServer {
	return strg
}

// API Storage disabled Store handler
func (strg *DisabledStorage) Store(ctx context.Context, request *StoreRequest) (*StoreResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Store not implemented")
}

// API Storage disabled Retrieve handler
func (strg *DisabledStorage) Retrieve(ctx context.Context, request *RetrieveRequest) (*RetrieveResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Retrieve not implemented")
}

// API Storage disabled Delete handler
func (strg *DisabledStorage) Delete(ctx context.Context, request *DeleteRequest) (*DeleteResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Deletenot implemented")
}

// API Storage disabled Update handler
func (strg *DisabledStorage) Update(ctx context.Context, request *UpdateRequest) (*UpdateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Update not implemented")
}
