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
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
	"encryption-service/scopes"
)

type UserAuthenticator struct {
	Cryptor interfaces.CryptorInterface
}

// NewUser creates an user of specified kind with random credentials in the authStorage
func (ua *UserAuthenticator) NewUser(ctx context.Context, userscopes scopes.ScopeType) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, "", errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	accessToken := NewAccessToken(userID, userscopes, time.Hour*24*365*150) // TODO: use duration longer than I will life

	token, err := accessToken.SerializeAccessToken(ua.Cryptor)
	if err != nil {
		return nil, "", err
	}

	// insert user for compatibility with the check in permissions_handler
	// we only need to know if a user exists there, thus it is only important
	// that a row exists
	err = authStorageTx.UpsertUser(ctx, userID)
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
// TODO: this is name is bad
func (ua *UserAuthenticator) ParseAccessToken(token string) (interfaces.AccessTokenInterface, error) {
	return ParseAccessToken(ua.Cryptor, token)
}
