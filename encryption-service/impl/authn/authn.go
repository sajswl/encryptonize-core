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
	"time"

	"github.com/gofrs/uuid"
	"google.golang.org/protobuf/proto"

	"encryption-service/contextkeys"
	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
	log "encryption-service/logger"
	"encryption-service/users"
)

type UserAuthenticator struct {
	TokenCryptor interfaces.CryptorInterface
	UserCryptor  interfaces.CryptorInterface
}

// NewUser creates an user of specified kind with random credentials in the authStorage
func (ua *UserAuthenticator) NewUser(ctx context.Context, userscopes users.ScopeType) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, "", errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	// user password creation

	pwd, salt, err := crypt.GenerateUserPassword()
	if err != nil {
		return nil, "", err
	}

	scopes, err := users.MapScopetypeToScopes(userscopes)
	if err != nil {
		return nil, "", err
	}

	confidential := users.ConfidentialUserData{
		HashedPassword: crypt.HashPassword(pwd, salt),
		Salt:           salt,
		Scopes:         scopes,
	}

	buf, err := proto.Marshal(&confidential)
	if err != nil {
		return nil, "", err
	}

	wrappedKey, ciphertext, err := ua.UserCryptor.Encrypt(buf, userID.Bytes())
	if err != nil {
		return nil, "", err
	}

	userData := users.UserData{
		UserID:               userID,
		ConfidentialUserData: ciphertext,
		WrappedKey:           wrappedKey,
	}

	// insert user for compatibility with the check in permissions_handler
	// we only need to know if a user exists there, thus it is only important
	// that a row exists
	err = authStorageTx.InsertUser(ctx, userData)
	if err != nil {
		return nil, "", err
	}

	err = authStorageTx.Commit(ctx)
	if err != nil {
		return nil, "", err
	}

	return &userID, pwd, nil
}

// LoginUser logs in a user
func (ua *UserAuthenticator) LoginUser(ctx context.Context, userID uuid.UUID, providedPassword string) (string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return "", errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	user, key, err := authStorageTx.GetUserData(ctx, userID)
	if err != nil {
		return "", err
	}

	userData, err := ua.UserCryptor.Decrypt(key, user, userID.Bytes())
	if err != nil {
		return "", err
	}

	var confidential users.ConfidentialUserData
	err = proto.Unmarshal(userData, &confidential)

	if err != nil {
		return "", err
	}

	if !crypt.CompareHashAndPassword(providedPassword, confidential.HashedPassword, confidential.Salt) {
		return "", errors.New("Incorrect password")
	}

	userscopes, err := users.MapScopesToScopeType(confidential.Scopes)
	if err != nil {
		return "", err
	}

	accessToken := NewAccessTokenDuration(userID, userscopes, time.Hour*24*365*150) // TODO: currently use a duration longer than I will survive

	token, err := accessToken.SerializeAccessToken(ua.TokenCryptor)
	if err != nil {
		return "", err
	}

	return token, nil
}

// NewAdminUser creates a new admin users with random credentials
// This function is intended to be used for cli operation
func (ua *UserAuthenticator) NewAdminUser(authStore interfaces.AuthStoreInterface) error {
	ctx := context.Background()

	// Need to inject requestID manually, as these calls don't pass the usual middleware
	requestID, err := uuid.NewV4()
	if err != nil {
		log.Fatal(ctx, err, "Could not generate uuid")
	}
	ctx = context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

	authStoreTx, err := authStore.NewTransaction(ctx)
	if err != nil {
		log.Fatal(ctx, err, "Authstorage Begin failed")
	}
	defer func() {
		err := authStoreTx.Rollback(ctx)
		if err != nil {
			log.Fatal(ctx, err, "Performing rollback")
		}
	}()

	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTx)
	adminScope := users.ScopeUserManagement
	userID, password, err := ua.NewUser(ctx, adminScope)
	if err != nil {
		log.Fatal(ctx, err, "Create user failed")
	}

	// I create a new context so that the user isn't confused by the requestId in the output
	ctx = context.TODO()
	log.Info(ctx, "Created admin user:")
	log.Infof(ctx, "    User ID:  %v", userID)
	log.Infof(ctx, "    Password: %v", password)

	return nil
}

// this function takes a user facing token and parses it into the internal
// access token format. It assumes that if the mac is valid the token information
// also is.
// TODO: this is name is bad
func (ua *UserAuthenticator) ParseAccessToken(token string) (interfaces.AccessTokenInterface, error) {
	return ParseAccessToken(ua.TokenCryptor, token)
}
