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

package authn

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/gofrs/uuid"

	"google.golang.org/protobuf/proto"

	"encryption-service/interfaces"
	"encryption-service/users"
)

var ErrTokenExpired = errors.New("token expired")

// AccessToken is the internal representation of an access token
type AccessToken struct {
	userID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption service to depend on its implementation
	userScopes users.ScopeType
	expiryTime int64
}

// NewAccessTokenDuration instantiates a new access token with user ID, user scopes and validity period
func NewAccessTokenDuration(userID uuid.UUID, userScopes users.ScopeType, validityPeriod time.Duration) *AccessToken {
	return NewAccessToken(userID, userScopes, time.Now().Add(validityPeriod))
}

// NewAccessToken does the same as NewAccessTokenDuration, except it takes a point in time at which the access token exires
func NewAccessToken(userID uuid.UUID, userScopes users.ScopeType, expiryTime time.Time) *AccessToken {
	return &AccessToken{
		userID:     userID,
		userScopes: userScopes,
		expiryTime: expiryTime.Unix(),
	}
}

func (at *AccessToken) UserID() uuid.UUID {
	return at.userID
}

func (at *AccessToken) UserScopes() users.ScopeType {
	return at.userScopes
}

func (at *AccessToken) HasScopes(tar users.ScopeType) bool {
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

	userScope, err := users.MapScopetypeToScopes(at.userScopes)
	if err != nil {
		return "", errors.New("Invalid scopes")
	}

	accessTokenClient := &users.AccessTokenClient{
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

// ParseAccessToken decrypts and deserializes an access token from a string.
// Additionally, it checks whether the token has expired, returning `ErrTokenExpired` if it as.
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

	accessTokenClient := &users.AccessTokenClient{}
	err = proto.Unmarshal(data, accessTokenClient)
	if err != nil {
		return nil, err
	}

	uuid, err := uuid.FromBytes(accessTokenClient.UserId)
	if err != nil {
		return nil, err
	}

	userScopes, err := users.MapScopesToScopeType(accessTokenClient.UserScopes)
	if err != nil {
		return nil, errors.New("Error mapping scopes in Token")
	}

	expiryTime := time.Unix(accessTokenClient.ExpiryTime, 0)
	if time.Now().After(expiryTime) {
		return nil, ErrTokenExpired
	}

	return &AccessToken{
		userID:     uuid,
		userScopes: userScopes,
		expiryTime: accessTokenClient.ExpiryTime,
	}, nil
}
