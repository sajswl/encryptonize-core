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

	"encryption-service/common"
	"encryption-service/interfaces"
)

var ErrTokenExpired = errors.New("token expired")

// AccessToken is the internal representation of an access token
type AccessToken struct {
	UserID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption service to depend on its implementation
	UserScopes common.ScopeType
	ExpiryTime time.Time
}

// NewAccessTokenDuration instantiates a new access token with user ID, user scopes and validity period
func NewAccessTokenDuration(userID uuid.UUID, userScopes common.ScopeType, validityPeriod time.Duration) *AccessToken {
	return NewAccessToken(userID, userScopes, time.Now().Add(validityPeriod))
}

// NewAccessToken does the same as NewAccessTokenDuration, except it takes a point in time at which the access token exires
func NewAccessToken(userID uuid.UUID, userScopes common.ScopeType, expiryTime time.Time) *AccessToken {
	return &AccessToken{
		UserID:     userID,
		UserScopes: userScopes,
		// Strip monotonic clock reading, as it has no meaning outside the current process.
		// For more info: https://pkg.go.dev/time#hdr-Monotonic_Clocks
		ExpiryTime: expiryTime.Round(0),
	}
}

func (at *AccessToken) GetUserID() uuid.UUID {
	return at.UserID
}

func (at *AccessToken) GetUserScopes() common.ScopeType {
	return at.UserScopes
}

func (at *AccessToken) HasScopes(tar common.ScopeType) bool {
	return at.GetUserScopes().HasScopes(tar)
}

// IsValid returns false if the token is expired, true otherwise.
func (at *AccessToken) IsValid() bool {
	return time.Now().Before(at.ExpiryTime)
}

// SerializeAccessToken encrypts and serializes an access token with a CryptorInterface
// Format (only used internally): base64_url(wrapped_key).base64_url(gob(enc(AccessToken)))
func (at *AccessToken) SerializeAccessToken(cryptor interfaces.CryptorInterface) (string, error) {
	//TODO not sure about these checks
	if at.GetUserScopes().IsValid() != nil {
		return "", errors.New("Invalid scopes")
	}

	if at.GetUserID().Version() != 4 || at.GetUserID().Variant() != uuid.VariantRFC4122 {
		return "", errors.New("Invalid userID UUID")
	}

	wrappedKey, ciphertext, err := cryptor.EncodeAndEncrypt(at, nil)
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

	accessToken := &AccessToken{}
	err = cryptor.DecodeAndDecrypt(accessToken, wrappedKey, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	if !accessToken.IsValid() {
		return nil, ErrTokenExpired
	}

	return accessToken, nil
}
