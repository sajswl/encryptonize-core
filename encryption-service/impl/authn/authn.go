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
	"bytes"
	context "context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid"

	"encryption-service/contextkeys"
	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
	log "encryption-service/logger"
	"encryption-service/users"
)

var ErrAuthStoreTxCastFailed = errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")

const tokenExpiryTime = time.Hour

type UserAuthenticator struct {
	TokenCryptor interfaces.CryptorInterface
	UserCryptor  interfaces.CryptorInterface
}

// NewUser creates an user of specified kind with random credentials in the authStorage
func (ua *UserAuthenticator) NewUser(ctx context.Context, userscopes users.ScopeType) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, "", ErrAuthStoreTxCastFailed
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

	confidential := &users.ConfidentialUserData{
		HashedPassword: crypt.HashPassword(pwd, salt),
		Salt:           salt,
		Scopes:         userscopes,
		// A user is a member of their own group
		GroupIDs: map[uuid.UUID]bool{userID: true},
	}

	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err = enc.Encode(confidential)
	if err != nil {
		return nil, "", err
	}

	data := buffer.Bytes()
	wrappedKey, ciphertext, err := ua.UserCryptor.Encrypt(data, userID.Bytes())
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

// GetUserData fetches the user's confidential data
func (ua *UserAuthenticator) GetUserData(ctx context.Context, userID uuid.UUID) (*users.ConfidentialUserData, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, ErrAuthStoreTxCastFailed
	}

	user, key, err := authStorageTx.GetUserData(ctx, userID)
	if err != nil {
		return nil, err
	}

	userData, err := ua.UserCryptor.Decrypt(key, user, userID.Bytes())
	if err != nil {
		return nil, err
	}

	confidential := &users.ConfidentialUserData{}
	dec := gob.NewDecoder(bytes.NewReader(userData))
	err = dec.Decode(confidential)
	if err != nil {
		return nil, err
	}

	return confidential, nil
}

// LoginUser logs in a user
func (ua *UserAuthenticator) LoginUser(ctx context.Context, userID uuid.UUID, providedPassword string) (string, error) {
	confidential, err := ua.GetUserData(ctx, userID)
	if err != nil {
		return "", err
	}

	if !crypt.CompareHashAndPassword(providedPassword, confidential.HashedPassword, confidential.Salt) {
		return "", errors.New("Incorrect password")
	}

	accessToken := NewAccessTokenDuration(userID, confidential.Scopes, tokenExpiryTime)

	token, err := accessToken.SerializeAccessToken(ua.TokenCryptor)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (ua *UserAuthenticator) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return ErrAuthStoreTxCastFailed
	}

	err := authStorageTx.RemoveUser(ctx, userID)
	if err != nil {
		return err
	}

	err = authStorageTx.Commit(ctx)
	if err != nil {
		return err
	}

	return nil
}

// NewCLIUser creates a new user with the requested scopes. This function is intended to be used for
// CLI operation.
func (ua *UserAuthenticator) NewCLIUser(scopes string, authStore interfaces.AuthStoreInterface) error {
	ctx := context.Background()

	// Parse user supplied scopes
	userScopes, err := users.MapStringToScopeType(scopes)
	if err != nil {
		return err
	}

	// Need to inject requestID manually, as these calls don't pass the usual middleware
	requestID, err := uuid.NewV4()
	if err != nil {
		log.Fatal(ctx, err, "Could not generate uuid")
	}
	ctx = context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

	authStoreTxCreate, err := authStore.NewTransaction(ctx)
	if err != nil {
		log.Fatal(ctx, err, "Authstorage Begin failed")
	}
	defer func() {
		err := authStoreTxCreate.Rollback(ctx)
		if err != nil {
			log.Fatal(ctx, err, "Performing rollback")
		}
	}()

	ctxCreate := context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTxCreate)
	userID, password, err := ua.NewUser(ctxCreate, userScopes)
	if err != nil {
		log.Fatal(ctxCreate, err, "Create user failed")
	}

	log.Info(ctx, "User created, printing to stdout")
	credentials, err := json.Marshal(
		struct {
			UserID   string `json:"user_id"`
			Password string `json:"password"`
		}{
			UserID:   userID.String(),
			Password: password,
		})
	if err != nil {
		log.Fatal(ctxCreate, err, "Create user failed")
	}
	fmt.Println(string(credentials))

	return nil
}

// this function takes a user facing token and parses it into the internal
// access token format. It assumes that if the mac is valid the token information
// also is.
// TODO: this is name is bad
func (ua *UserAuthenticator) ParseAccessToken(token string) (interfaces.AccessTokenInterface, error) {
	return ParseAccessToken(ua.TokenCryptor, token)
}
