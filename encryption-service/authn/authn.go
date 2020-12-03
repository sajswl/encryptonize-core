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
	CreateOrUpdateUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userKind UserKindType) error
	LoginUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userKind UserKindType) (bool, error)
}

// UserKindType represents the different types of users of the Authenticator
type UserKindType uint64

const (
	UserKind UserKindType = iota
	AdminKind
)

// IsValid checks if a UserKind is valid since go doesn't support type safe enums
func (ut UserKindType) IsValid() error {
	switch ut {
	case UserKind, AdminKind:
		return nil
	}
	return errors.New("invalid user type")
}

// formatMessage formats a message of userID + accessToken + userKind for signing
// Message: userID (UUID) - 16 bytes | accessToken - 32 bytes | userKind - 8 bytes little endian encoded
func formatMessage(userID uuid.UUID, accessToken []byte, userKind UserKindType) ([]byte, error) {
	if userID.Version() != 4 || userID.Variant() != uuid.VariantRFC4122 {
		return nil, errors.New("invalid user ID UUID version or variant")
	}

	if len(accessToken) != 32 {
		return nil, errors.New("invalid access token length")
	}

	err := userKind.IsValid()
	if err != nil {
		return nil, err
	}
	msg := make([]byte, len(userID)+len(accessToken)+8)
	copy(msg, userID.Bytes())
	copy(msg[len(userID):], accessToken)
	binary.LittleEndian.PutUint64(msg[len(userID)+len(accessToken):], uint64(userKind))

	return msg, nil
}

// tag creates a tag of userID + accessToken + userKind
func (a *Authenticator) tag(userID uuid.UUID, accessToken []byte, userKind UserKindType) ([]byte, error) {
	msg, err := formatMessage(userID, accessToken, userKind)
	if err != nil {
		return nil, err
	}
	return a.MessageAuthenticator.Tag(crypt.UsersDomain, msg)
}

// verify verifies a tag of usersID + accessToken + userKind
func (a *Authenticator) verify(userID uuid.UUID, accessToken []byte, userKind UserKindType, tag []byte) (bool, error) {
	msg, err := formatMessage(userID, accessToken, userKind)
	if err != nil {
		return false, err
	}
	return a.MessageAuthenticator.Verify(crypt.UsersDomain, msg, tag)
}

// CreateOrUpdateUser creates (or updates) a user: userID + accessToken + userKind for the tx (Auth Storage)
func (a *Authenticator) CreateOrUpdateUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userKind UserKindType) error {
	tag, err := a.tag(userID, accessToken, userKind)
	if err != nil {
		return err
	}
	return a.AuthStore.UpsertUser(ctx, userID, tag)
}

// LoginUser checks if an user: userID + accesstoken + userKind exists for the tx (Auth Storage)
func (a *Authenticator) LoginUser(ctx context.Context, userID uuid.UUID, accessToken []byte, userKind UserKindType) (bool, error) {
	storedTag, err := a.AuthStore.GetUserTag(ctx, userID)
	if err != nil {
		return false, err
	}
	return a.verify(userID, accessToken, userKind, storedTag)
}
