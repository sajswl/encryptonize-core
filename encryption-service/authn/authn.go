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
package authn

import (
	"context"
	"encoding/binary"
	"errors"

	"github.com/gofrs/uuid"

	"encryption-service/authstorage"
	"encryption-service/crypt"
)

// Authenticator represents a MessageAuthenticator used for creating and logging in users
type Authenticator struct {
	MessageAuthenticator *crypt.MessageAuthenticator
	AuthStore            authstorage.AuthStoreInterface
}

type AuthenticatorInterface interface {
	CreateOrUpdateUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userScope ScopeType) error
	LoginUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userScope ScopeType) (bool, error)
}

// ScopeType represents the different scopes a user could be granted
type ScopeType uint64

const (
	ScopeRead ScopeType = 1 << iota
	ScopeCreate
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

func (us ScopeType) IsValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

// formatMessage formats a message of userID + accessToken + userScope for signing
// Message: userID (UUID) - 16 bytes | accessToken - 32 bytes | userScope - 8 bytes little endian encoded
func formatMessage(userID uuid.UUID, accessToken []byte, userScope ScopeType) ([]byte, error) {
	if userID.Version() != 4 || userID.Variant() != uuid.VariantRFC4122 {
		return nil, errors.New("invalid user ID UUID version or variant")
	}

	if len(accessToken) != 32 {
		return nil, errors.New("invalid access token length")
	}

	if userScope >= ScopeEnd {
		return nil, errors.New("invalid scopes")
	}

	msg := make([]byte, len(userID)+len(accessToken)+8)
	copy(msg, userID.Bytes())
	copy(msg[len(userID):], accessToken)
	binary.LittleEndian.PutUint64(msg[len(userID)+len(accessToken):], uint64(userScope))

	return msg, nil
}

// tag creates a tag of userID + accessToken + userScope
func (a *Authenticator) tag(userID uuid.UUID, accessToken []byte, userScope ScopeType) ([]byte, error) {
	msg, err := formatMessage(userID, accessToken, userScope)
	if err != nil {
		return nil, err
	}
	return a.MessageAuthenticator.Tag(crypt.UsersDomain, msg)
}

// verify verifies a tag of usersID + accessToken + userScope
func (a *Authenticator) verify(userID uuid.UUID, accessToken []byte, userScope ScopeType, tag []byte) (bool, error) {
	msg, err := formatMessage(userID, accessToken, userScope)
	if err != nil {
		return false, err
	}
	return a.MessageAuthenticator.Verify(crypt.UsersDomain, msg, tag)
}

// CreateOrUpdateUser creates (or updates) a user: userID + accessToken + userScope for the tx (Auth Storage)
func (a *Authenticator) CreateOrUpdateUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userScope ScopeType) error {
	tag, err := a.tag(userID, accessToken, userScope)
	if err != nil {
		return err
	}
	return a.AuthStore.UpsertUser(ctx, userID, tag)
}

// LoginUser checks if an user: userID + accesstoken + userScope exists for the tx (Auth Storage)
func (a *Authenticator) LoginUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userScope ScopeType) (bool, error) {
	storedTag, err := a.AuthStore.GetUserTag(ctx, userID)
	if err != nil {
		return false, err
	}
	return a.verify(userID, accessToken, userScope, storedTag)
}
