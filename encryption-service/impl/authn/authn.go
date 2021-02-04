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
	context "context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
	"encryption-service/scopes"
)

type UserAuthenticator struct {
	Authenticator interfaces.MessageAuthenticatorInterface
}

// createUserWrapper creates an user of specified kind with random credentials in the authStorage
func (ua *UserAuthenticator) NewUser(ctx context.Context, userscopes scopes.ScopeType) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, "", errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	accessToken := &AccessToken{
		userID:     userID,
		userScopes: userscopes,
	}

	token, err := accessToken.SerializeAccessToken(ua.Authenticator)
	if err != nil {
		return nil, "", err
	}

	// insert user for compatibility with the check in permissions_handler
	// we only need to know if a user exists there, thus it is only important
	// that a row exists
	err = authStorageTx.UpsertUser(ctx, userID, []byte{})
	if err != nil {
		return nil, "", err
	}

	err = authStorageTx.Commit(ctx)
	if err != nil {
		return nil, "", err
	}

	return &userID, token, nil
}

// NewAdminUser creates a new admin users with random credentials
// This function is intended to be used for cli operation
func (ua *UserAuthenticator) NewAdminUser(authStore interfaces.AuthStoreInterface) error {
	ctx := context.Background()

	// Need to inject requestID manually, as these calls don't pass the usual middleware
	requestID, err := uuid.NewV4()
	if err != nil {
		log.Fatal(ctx, "Could not generate uuid", err)
	}
	ctx = context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

	authStoreTx, err := authStore.NewTransaction(ctx)
	if err != nil {
		log.Fatal(ctx, "Authstorage Begin failed", err)
	}
	defer func() {
		err := authStoreTx.Rollback(ctx)
		if err != nil {
			log.Fatal(ctx, "Performing rollback", err)
		}
	}()

	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTx)
	adminScope := scopes.ScopeUserManagement
	userID, accessToken, err := ua.NewUser(ctx, adminScope)
	if err != nil {
		log.Fatal(ctx, "Create user failed", err)
	}

	log.Info(ctx, "Created admin user:")
	log.Info(ctx, fmt.Sprintf("    User ID:      %v", userID))
	log.Info(ctx, fmt.Sprintf("    Access Token: %v", accessToken))

	return nil
}

// this function takes a user facing token and parses it into the internal
// access token format. It assumes that if the mac is valid the token information
// also is.
func (ua *UserAuthenticator) ParseAccessToken(token string) (interfaces.AccessTokenInterface, error) {
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
	valid, err := ua.Authenticator.Verify(msg, tag)
	if err != nil {
		return nil, err
	}

	if !valid {
		return nil, errors.New("invalid token")
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
	return &AccessToken{
		userID:     uuid,
		userScopes: userScopes,
	}, nil
}
