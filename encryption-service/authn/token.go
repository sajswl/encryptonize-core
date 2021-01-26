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

	"encryption-service/crypt"
)

// ScopeType represents the different scopes a user could be granted
type ScopeType uint64

const ScopeNone ScopeType = 0
const (
	ScopeRead ScopeType = 1 << iota
	ScopeCreate
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

func (us ScopeType) isValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

func (us ScopeType) hasScopes(tar ScopeType) bool {
	return (us & tar) == tar
}

type AccessToken struct {
	UserID uuid.UUID
	// this field is not exported to prevent other parts
	// of the encryption service to depend on its implementation
	userScopes ScopeType
}

// creates an access token only if the arguments are valid
func (a *AccessToken) New(userID uuid.UUID, userScopes ScopeType) error {
	if userID.Version() != 4 || userID.Variant() != uuid.VariantRFC4122 {
		return errors.New("invalid user ID UUID version or variant")
	}

	if err := userScopes.isValid(); err != nil {
		return err
	}

	a.UserID = userID
	a.userScopes = userScopes
	return nil
}

func (a *AccessToken) HasScopes(scopes ScopeType) bool {
	return a.userScopes.hasScopes(scopes)
}

// serializes an access token together with a random value. The random
// value ensures unique user facing token even if the actual access token
// would be equal. It also checks the validity of the access token as
// this is last function every token has to go through before the token
// are presented to an API. If this method only signs valid token we
// can then assume that any signed token is valid.
// This may not hold in when an encryption server was compromised.
// The returned token has three parts. Each part is individually base64url encoded
// the first part (data) is a serialized protobuf message containing
// the user ID and a set of scopes. The structure of the assembled token is
// <data>.<nonce>.HMAC(nonce||data)
func (a *Authenticator) SerializeAccessToken(accessToken *AccessToken) (string, error) {
	nonce, err := crypt.Random(16)
	if err != nil {
		return "", err
	}

	if accessToken.userScopes.isValid() != nil {
		return "", errors.New("Invalid scopes")
	}

	if accessToken.UserID.Version() != 4 || accessToken.UserID.Variant() != uuid.VariantRFC4122 {
		return "", errors.New("Invalid userID UUID")
	}

	userScope := []UserScope{}
	// scopes is a bitmap. This checks each bit individually
	for i := ScopeType(1); i < ScopeEnd; i <<= 1 {
		if !accessToken.userScopes.hasScopes(i) {
			continue
		}
		switch i {
		case ScopeRead:
			userScope = append(userScope, UserScope_READ)
		case ScopeCreate:
			userScope = append(userScope, UserScope_CREATE)
		case ScopeIndex:
			userScope = append(userScope, UserScope_INDEX)
		case ScopeObjectPermissions:
			userScope = append(userScope, UserScope_OBJECTPERMISSIONS)
		case ScopeUserManagement:
			userScope = append(userScope, UserScope_USERMANAGEMENT)
		default:
			return "", errors.New("Invalid scopes")
		}
	}

	accessTokenClient := &AccessTokenClient{
		UserId:     accessToken.UserID.Bytes(),
		UserScopes: userScope,
	}

	data, err := proto.Marshal(accessTokenClient)
	if err != nil {
		return "", err
	}

	msg := append(nonce, data...)
	tag, err := a.MessageAuthenticator.Tag(crypt.TokenDomain, msg)
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
func (a *Authenticator) ParseAccessToken(token string) (*AccessToken, error) {
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
	valid, err := a.MessageAuthenticator.Verify(crypt.TokenDomain, msg, tag)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid token")
	}

	accessTokenClient := &AccessTokenClient{}
	err = proto.Unmarshal(data, accessTokenClient)
	if err != nil {
		return nil, err
	}

	uuid, err := uuid.FromBytes(accessTokenClient.UserId)
	if err != nil {
		return nil, err
	}

	var userScopes ScopeType
	for _, scope := range accessTokenClient.UserScopes {
		switch scope {
		case UserScope_READ:
			userScopes |= ScopeRead
		case UserScope_CREATE:
			userScopes |= ScopeCreate
		case UserScope_INDEX:
			userScopes |= ScopeIndex
		case UserScope_OBJECTPERMISSIONS:
			userScopes |= ScopeObjectPermissions
		case UserScope_USERMANAGEMENT:
			userScopes |= ScopeUserManagement
		default:
			return nil, errors.New("Invalid Scopes in Token")
		}
	}
	return &AccessToken{
		UserID:     uuid,
		userScopes: userScopes,
	}, nil
}
