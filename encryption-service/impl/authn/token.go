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
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/gofrs/uuid"

	"google.golang.org/protobuf/proto"

	"encryption-service/interfaces"
	"encryption-service/scopes"
)

// AccessToken is the internal representation of an access token
type AccessToken struct {
	userID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption service to depend on its implementation
	userScopes scopes.ScopeType
	expiryTime int64
}

// NewAccessToken instantiates a new access token with user ID, user scopes and validity period
func NewAccessToken(userID uuid.UUID, userScopes scopes.ScopeType, validityPeriod time.Duration) *AccessToken {
	expiryTime := time.Now().Add(validityPeriod).Unix()
	return &AccessToken{
		userID:     userID,
		userScopes: userScopes,
		expiryTime: expiryTime,
	}
}

func (at *AccessToken) UserID() uuid.UUID {
	return at.userID
}

func (at *AccessToken) UserScopes() scopes.ScopeType {
	return at.userScopes
}

func (at *AccessToken) HasScopes(tar scopes.ScopeType) bool {
	return at.UserScopes().HasScopes(tar)
}

// SerializeAccessToken encrypts and serializes an access token with a CryptorInterface
// Format (only used internally): base64_url(wrapped_key).base64_url(proto_marshal(AccessTokenClient))
func (at *AccessToken) SerializeAccessToken(cryptor interfaces.CryptorInterface) (string, error) {
	//TODO not sure about these checks
	if at.UserScopes().IsValid() != nil {
		return "", errors.New("Invalid scopes")
	}

	if at.UserID().Version() != 4 || at.UserID().Variant() != uuid.VariantRFC4122 {
		return "", errors.New("Invalid userID UUID")
	}

	userScope := []scopes.UserScope{}
	// scopes is a bitmap. This checks each bit individually
	for i := scopes.ScopeType(1); i < scopes.ScopeEnd; i <<= 1 {
		if !at.HasScopes(i) {
			continue
		}
		switch i {
		case scopes.ScopeRead:
			userScope = append(userScope, scopes.UserScope_READ)
		case scopes.ScopeCreate:
			userScope = append(userScope, scopes.UserScope_CREATE)
		case scopes.ScopeIndex:
			userScope = append(userScope, scopes.UserScope_INDEX)
		case scopes.ScopeObjectPermissions:
			userScope = append(userScope, scopes.UserScope_OBJECTPERMISSIONS)
		case scopes.ScopeUserManagement:
			userScope = append(userScope, scopes.UserScope_USERMANAGEMENT)
		default:
			return "", errors.New("Invalid scopes")
		}
	}

	accessTokenClient := &scopes.AccessTokenClient{
		UserId:     at.UserID().Bytes(),
		UserScopes: userScope,
		ExpiryTime: at.expiryTime,
	}

	data, err := proto.Marshal(accessTokenClient)
	if err != nil {
		return "", err
	}

	wrappedKey, ciphertext, err := cryptor.Encrypt(data, nil)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(wrappedKey) + "." + base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// ParseAccessToken decrypts and unserializes an access token from a string.
// Addtionally, it checks if the token hasn't expired.
func ParseAccessToken(cryptor interfaces.CryptorInterface, token string) (*AccessToken, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 2 {
		return nil, errors.New("invalid token format")
	}

	wrappedKey, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, errors.New("invalid wrappedKey portion of token")
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, errors.New("invalid ciphertext portion of token")
	}

	data, err := cryptor.Decrypt(wrappedKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	accessTokenClient := &scopes.AccessTokenClient{}
	err = proto.Unmarshal(data, accessTokenClient)
	if err != nil {
		return nil, err
	}

	uuid, err := uuid.FromBytes(accessTokenClient.UserId)
	if err != nil {
		return nil, err
	}

	var userScopes scopes.ScopeType
	for _, scope := range accessTokenClient.UserScopes {
		switch scope {
		case scopes.UserScope_READ:
			userScopes |= scopes.ScopeRead
		case scopes.UserScope_CREATE:
			userScopes |= scopes.ScopeCreate
		case scopes.UserScope_INDEX:
			userScopes |= scopes.ScopeIndex
		case scopes.UserScope_OBJECTPERMISSIONS:
			userScopes |= scopes.ScopeObjectPermissions
		case scopes.UserScope_USERMANAGEMENT:
			userScopes |= scopes.ScopeUserManagement
		default:
			return nil, errors.New("Invalid Scopes in Token")
		}
	}

	expiryTime := time.Unix(accessTokenClient.ExpiryTime, 0)
	if time.Now().After(expiryTime) {
		return nil, errors.New("token expired")
	}

	return &AccessToken{
		userID:     uuid,
		userScopes: userScopes,
		expiryTime: accessTokenClient.ExpiryTime,
	}, nil
}
