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

	"github.com/gofrs/uuid"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
	"encryption-service/scopes"
)

type UserAuthenticator struct {
}

// createUserWrapper creates an user of specified kind with random credentials in the authStorage
func (ua *UserAuthenticator) NewUser(ctx context.Context, userscopes scopes.ScopeType, authenticator interfaces.MessageAuthenticatorInterface) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, "", errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	accessToken := &AccessToken{
		UserID:     userID,
		UserScopes: userscopes,
	}

	token, err := accessToken.SerializeAccessToken(authenticator)
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

// CreateAdminCommand creates a new admin users with random credentials
// This function is intended to be used for cli operation
func (ua *UserAuthenticator) CreateAdminCommand(authStore interfaces.AuthStoreInterface, authenticator interfaces.MessageAuthenticatorInterface) error {
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
	userID, accessToken, err := ua.NewUser(ctx, adminScope, authenticator)
	if err != nil {
		log.Fatal(ctx, "Create user failed", err)
	}

	log.Info(ctx, "Created admin user:")
	log.Info(ctx, fmt.Sprintf("    User ID:      %v", userID))
	log.Info(ctx, fmt.Sprintf("    Access Token: %v", accessToken))

	return nil
}
