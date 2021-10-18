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

	"encryption-service/users"
)

var ErrNotFound = errors.New("not found")

// Interface representing a connection to the Auth Store
type AuthStoreInterface interface {
	// Creates a new transaction
	NewTransaction(ctx context.Context) (authStoreTx AuthStoreTxInterface, err error)

	// Closes the connection
	Close()
}

// Interface representing a transaction on the Auth Store
type AuthStoreTxInterface interface {
	// Rollback any changes
	Rollback(ctx context.Context) (err error)

	// Commit any changes
	Commit(ctx context.Context) (err error)

	// Check if a user exists in the auth store
	UserExists(ctx context.Context, userID uuid.UUID) (res bool, err error)

	// Get user's confidential data
	GetUserData(ctx context.Context, userID uuid.UUID) (userData []byte, key []byte, err error)

	// Insert a user
	InsertUser(ctx context.Context, userData users.UserData) (err error)

	// Removes a user
	RemoveUser(ctx context.Context, userID uuid.UUID) (err error)

	//  Retrieve an existing access object
	GetAccessObject(ctx context.Context, objectID uuid.UUID) (object, tag []byte, err error)

	// Insert a new access object
	InsertAcccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) (err error)

	// Update an existing access object
	UpdateAccessObject(ctx context.Context, objectID uuid.UUID, data, tag []byte) (err error)

	// Delete an existing access object
	DeleteAccessObject(ctx context.Context, objectID uuid.UUID) (err error)
}

// Interface representing a connection to the object store
type ObjectStoreInterface interface {
	// Store an object under a given object ID
	Store(ctx context.Context, objectID string, object []byte) (err error)

	// Retrieve an object with a given object ID
	Retrieve(ctx context.Context, objectID string) (object []byte, err error)

	// Delete an object with a given object ID
	Delete(ctx context.Context, objectID string) (err error)
}

// CryptorInterface offers an API to encrypt / decrypt data and additional associated data with a (wrapped) random key
type CryptorInterface interface {
	// Encrypt encrypts data + aad with a random key and return the wrapped key and the ciphertext
	Encrypt(data, aad []byte) (wrappedKey, ciphertext []byte, err error)

	// EncryptWithKey encrypts data + aad with a wrapped key and returns the ciphertext
	EncryptWithKey(data, aad, key []byte) (ciphertext []byte, err error)

	// Decrypt decrypts a ciphertext + aad with a wrapped key
	Decrypt(wrappedKey, ciphertext, aad []byte) (plaintext []byte, err error)
}

// KeyWrapperInterface offers an API to wrap / unwrap key material
type KeyWrapperInterface interface {
	//Wrap wraps the provided key material.
	Wrap(data []byte) ([]byte, error)

	// Unwrap unwraps a wrapped key.
	Unwrap(data []byte) ([]byte, error)
}

// Interface for authenticating and creating users
type UserAuthenticatorInterface interface {
	// Create a new user with the requested scopes
	NewUser(ctx context.Context, userscopes users.ScopeType) (userID *uuid.UUID, password string, err error)

	// Create a new user with the requested scopes
	NewCLIUser(scopes string, authStore AuthStoreInterface) (err error)

	// Parses a token string into the internal data type
	ParseAccessToken(token string) (tokenStruct AccessTokenInterface, err error)

	// Logs a user in with userID and password pair
	LoginUser(ctx context.Context, userID uuid.UUID, password string) (string, error)

	// Removes a user
	RemoveUser(ctx context.Context, userID uuid.UUID) (err error)
}

type AccessObjectInterface interface {
	// AddUser adds a user to the permission list
	AddUser(targetUserID uuid.UUID)

	// RemoveUser Removes a user from the permission list
	RemoveUser(targetUserID uuid.UUID)

	// GetUsers returns the list of users that may access the object
	GetUsers() (userIDs []uuid.UUID, err error)

	// ContainsUser checks if the user is present in the permission list
	ContainsUser(targetUserID uuid.UUID) (exists bool)

	// getWOEK retrieves the wrapped object encryption key
	GetWOEK() (woek []byte)
}

// Interface for authenticating and creating Access Objects
type AccessObjectAuthenticatorInterface interface {
	// Creates a new Access Object and inserts it into the Authstorage
	CreateAccessObject(ctx context.Context, objectID, userID uuid.UUID, woek []byte) (err error)

	// Fetches an existing Access Object
	FetchAccessObject(ctx context.Context, objectID uuid.UUID) (accessObject AccessObjectInterface, err error)

	// Updates or inserts the AccessObject into backend storage
	UpsertAccessObject(ctx context.Context, objectID uuid.UUID, accessObject AccessObjectInterface) (err error)

	// Deletes an existing Access Object
	DeleteAccessObject(ctx context.Context, objectID uuid.UUID) (err error)
}

// Interface for authentication of data
type MessageAuthenticatorInterface interface {
	// Create a tag for the given message
	Tag(msg []byte) (tag []byte, err error)

	// Check whether a tag matches the given message
	Verify(msg, msgTag []byte) (res bool, err error)
}

// Interface representing an access token
type AccessTokenInterface interface {
	// Get the user ID contained in the token
	UserID() (userID uuid.UUID)

	// Get the scopes contained in the token
	UserScopes() (scopes users.ScopeType)

	// Check if the token contains specific scopes
	HasScopes(tar users.ScopeType) (res bool)
}
