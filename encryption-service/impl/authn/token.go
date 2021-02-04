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

	"google.golang.org/protobuf/proto"

	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
	"encryption-service/scopes"
)

type AccessToken struct {
	userID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption service to depend on its implementation
	userScopes scopes.ScopeType
}

func NewAccessToken(userID uuid.UUID, userScopes scopes.ScopeType) AccessToken {
	return AccessToken{
		userID:     userID,
		userScopes: userScopes,
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
	}

	data, err := proto.Marshal(accessTokenClient)
	if err != nil {
		return "", err
	}

	msg := append(nonce, data...)
	tag, err := authenticator.Tag(msg)
	if err != nil {
		return "", err
	}

	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)
	dataStr := base64.RawURLEncoding.EncodeToString(data)
	tagStr := base64.RawURLEncoding.EncodeToString(tag)

	return dataStr + "." + nonceStr + "." + tagStr, nil
}
