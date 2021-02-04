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

package interfaces

import (
	"context"
	"errors"

	"github.com/gofrs/uuid"

	"encryption-service/scopes"
)

// Interface representing a connection to the Auth Store
type AuthStoreInterface interface {
	NewTransaction(ctx context.Context) (AuthStoreTxInterface, error)
	Close()
}

// Interface representing a transaction on the Auth Store
type AuthStoreTxInterface interface {
	Rollback(ctx context.Context) error
	Commit(ctx context.Context) error

	// User handling
	GetUserTag(ctx context.Context, userID uuid.UUID) ([]byte, error)
	UpsertUser(ctx context.Context, userID uuid.UUID, tag []byte) error

	// Access Object handling
	GetAccessObject(ctx context.Context, objectID uuid.UUID) ([]byte, []byte, error)
	InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
	UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) error
}

// ErrNoRows : Return this error when an empty record set is returned for the DB
// e.g. when a users isn't found
var ErrNoRows = errors.New("no rows in result set")

type ObjectStoreInterface interface {
	// Store an object under a given object ID
	Store(ctx context.Context, objectID string, object []byte) error

	// Retrieve an object with a given object ID
	Retrieve(ctx context.Context, objectID string) ([]byte, error)
}

// Interface representing crypto functionality
type CrypterInterface interface {
	Encrypt(plaintext, aad, key []byte) ([]byte, error)
	Decrypt(ciphertext, aad, key []byte) ([]byte, error)
}

type UserAuthenticatorInterface interface {
	NewUser(ctx context.Context, userscopes scopes.ScopeType) (*uuid.UUID, string, error)
	NewAdminUser(authStore AuthStoreInterface) error
	ParseAccessToken(token string) (AccessTokenInterface, error)
}

type MessageAuthenticatorInterface interface {
	Tag(msg []byte) ([]byte, error)
	Verify(msg, msgTag []byte) (bool, error)
}

type AccessTokenInterface interface {
	UserID() uuid.UUID
	UserScopes() scopes.ScopeType
	HasScopes(tar scopes.ScopeType) bool
}
