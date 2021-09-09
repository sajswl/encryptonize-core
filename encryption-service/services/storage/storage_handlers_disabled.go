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
	log "encryption-service/logger"
)

type Disabled struct {
	UnimplementedEncryptonizeServer
}

// API Storage disabled Store handler
func (strg *Disabled) Store(ctx context.Context, request *StoreRequest) (*StoreResponse, error) {
	log.Info(ctx, "Store: Requested inactive endpoint")
	return strg.UnimplementedEncryptonizeServer.Store(ctx, request)
}

// API Storage disabled Retrieve handler
func (strg *Disabled) Retrieve(ctx context.Context, request *RetrieveRequest) (*RetrieveResponse, error) {
	log.Info(ctx, "Retrieve: Requested inactive endpoint")
	return strg.UnimplementedEncryptonizeServer.Retrieve(ctx, request)
}

// API Storage disabled Delete handler
func (strg *Disabled) Delete(ctx context.Context, request *DeleteRequest) (*DeleteResponse, error) {
	log.Info(ctx, "Delete: Requested inactive endpoint")
	return strg.UnimplementedEncryptonizeServer.Delete(ctx, request)
}

// API Storage disabled Update handler
func (strg *Disabled) Update(ctx context.Context, request *UpdateRequest) (*UpdateResponse, error) {
	log.Info(ctx, "Update: Requested inactive endpoint")
	return strg.UnimplementedEncryptonizeServer.Update(ctx, request)
}
