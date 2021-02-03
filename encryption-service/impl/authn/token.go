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
	"github.com/gofrs/uuid"
	"strings"

	"google.golang.org/protobuf/proto"

	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
	"encryption-service/scopes"
	authnsvc "encryption-service/services/authn"
)

type AccessToken struct {
	UserID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption service to depend on its implementation
	UserScopes scopes.ScopeType
}

func (at *AccessToken) UseID() uuid.UUID {
	return at.UserID
}

func (at *AccessToken) HasScopes(tar scopes.ScopeType) bool {
	return at.UserScopes.HasScopes(tar)
}

// serializes an access token together with a random value. The random
// value ensures unique user facing token even if the actual access token
// would be equal. It also checks the validity of the access token as
// this is last function every token has to go through before the token
// are presented to an API. If this method only signs valid token we
// can then assume that any signed token is valid.
// The returned token has three parts. Each part is individually base64url encoded
// the first part (data) is a serialized protobuf message containing
// the user ID and a set of scopes. The structure of the assembled token is
// <data>.<nonce>.HMAC(nonce||data)
func (at *AccessToken) SerializeAccessToken(authenticator interfaces.MessageAuthenticatorInterface) (string, error) {
	nonce, err := crypt.Random(16)
	if err != nil {
		return "", err
	}

	if at.UserScopes.IsValid() != nil {
		return "", errors.New("Invalid scopes")
	}

	if at.UserID.Version() != 4 || at.UserID.Variant() != uuid.VariantRFC4122 {
		return "", errors.New("Invalid userID UUID")
	}

	userScope := []authnsvc.UserScope{}
	// scopes is a bitmap. This checks each bit individually
	for i := scopes.ScopeType(1); i < scopes.ScopeEnd; i <<= 1 {
		if !at.HasScopes(i) {
			continue
		}
		switch i {
		case scopes.ScopeRead:
			userScope = append(userScope, authnsvc.UserScope_READ)
		case scopes.ScopeCreate:
			userScope = append(userScope, authnsvc.UserScope_CREATE)
		case scopes.ScopeIndex:
			userScope = append(userScope, authnsvc.UserScope_INDEX)
		case scopes.ScopeObjectPermissions:
			userScope = append(userScope, authnsvc.UserScope_OBJECTPERMISSIONS)
		case scopes.ScopeUserManagement:
			userScope = append(userScope, authnsvc.UserScope_USERMANAGEMENT)
		default:
			return "", errors.New("Invalid scopes")
		}
	}

	accessTokenClient := &authnsvc.AccessTokenClient{
		UserId:     at.UserID.Bytes(),
		UserScopes: userScope,
	}

	data, err := proto.Marshal(accessTokenClient)
	if err != nil {
		return "", err
	}

	msg := append(nonce, data...)
	tag, err := a.TokenMAC.Tag(msg)
	if err != nil {
		return "", err
	}

	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)
	dataStr := base64.RawURLEncoding.EncodeToString(data)
	tagStr := base64.RawURLEncoding.EncodeToString(tag)

	return dataStr + "." + nonceStr + "." + tagStr, nil
}

// this function takes a user facing token and parses it into the internal
// access token format. It assumes that if the mac is valid the token information
// also is.
func (at *AccessToken) ParseAccessToken(token string, authenticator interfaces.MessageAuthenticatorInterface) (*AccessToken, error) {
	tokenParts := strings.Split(token, ".")
	if len(tokenParts) != 3 {
		return nil, errors.New("invalid token format")
	}

	data, err := base64.RawURLEncoding.DecodeString(tokenParts[0])
	if err != nil {
		return nil, errors.New("invalid data portion of token")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return nil, errors.New("invalid nonce portion of token")
	}

	tag, err := base64.RawURLEncoding.DecodeString(tokenParts[2])
	if err != nil {
		return nil, errors.New("invalid tag portion of token")
	}

	msg := append(nonce, data...)
	valid, err := a.TokenMAC.Verify(msg, tag)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid token")
	}

	accessTokenClient := &authnsvc.AccessTokenClient{}
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
		case authnsvc.UserScope_READ:
			userScopes |= scopes.ScopeRead
		case authnsvc.UserScope_CREATE:
			userScopes |= scopes.ScopeCreate
		case authnsvc.UserScope_INDEX:
			userScopes |= scopes.ScopeIndex
		case authnsvc.UserScope_OBJECTPERMISSIONS:
			userScopes |= scopes.ScopeObjectPermissions
		case authnsvc.UserScope_USERMANAGEMENT:
			userScopes |= scopes.ScopeUserManagement
		default:
			return nil, errors.New("Invalid Scopes in Token")
		}
	}
	return &AccessToken{
		UserID:     uuid,
		UserScopes: userScopes,
	}, nil
}
