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

	"encryption-service/common"
	"encryption-service/impl/crypt"
	"encryption-service/interfaces"
)

var ErrAuthStoreTxCastFailed = errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")

const tokenExpiryTime = time.Hour

type UserAuthenticator struct {
	TokenCryptor interfaces.CryptorInterface
	UserCryptor  interfaces.CryptorInterface
	GroupCryptor interfaces.CryptorInterface
}

func (ua *UserAuthenticator) newUserData() (*common.ProtectedUserData, string, error) {
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	// user password creation
	pwd, salt, err := crypt.GenerateUserPassword()
	if err != nil {
		return nil, "", err
	}

	userData := &common.UserData{
		HashedPassword: crypt.HashPassword(pwd, salt),
		Salt:           salt,
		// A user is a member of their own group
		GroupIDs: map[uuid.UUID]bool{userID: true},
	}

	wrappedKey, ciphertext, err := ua.UserCryptor.EncodeAndEncrypt(userData, userID.Bytes())
	if err != nil {
		return nil, "", err
	}

	protected := &common.ProtectedUserData{
		UserID:     userID,
		UserData:   ciphertext,
		WrappedKey: wrappedKey,
	}

	return protected, pwd, nil
}

// NewUser creates an user of specified kind with random credentials in the authStorage
func (ua *UserAuthenticator) NewUser(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, "", ErrAuthStoreTxCastFailed
	}

	// Create the user iteself
	userData, pwd, err := ua.newUserData()
	if err != nil {
		return nil, "", err
	}

	err = authStorageTx.InsertUser(ctx, userData)
	if err != nil {
		return nil, "", err
	}

	// Create the user's group
	groupData, err := ua.newGroupData(userData.UserID, scopes)
	if err != nil {
		return nil, "", err
	}

	err = authStorageTx.InsertGroup(ctx, groupData)
	if err != nil {
		return nil, "", err
	}

	return &userData.UserID, pwd, nil
}

func (ua *UserAuthenticator) UpdateUser(ctx context.Context, userID uuid.UUID, userData *common.UserData) error {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return ErrAuthStoreTxCastFailed
	}

	wrappedKey, ciphertext, err := ua.UserCryptor.EncodeAndEncrypt(userData, userID.Bytes())
	if err != nil {
		return err
	}

	protected := &common.ProtectedUserData{
		UserID:     userID,
		UserData:   ciphertext,
		WrappedKey: wrappedKey,
	}

	return authStorageTx.UpdateUser(ctx, protected)
}

// GetUserData fetches the user's confidential data
func (ua *UserAuthenticator) GetUserData(ctx context.Context, userID uuid.UUID) (*common.UserData, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}

	protected, err := authStorageTx.GetUserData(ctx, userID)
	if err != nil {
		return nil, err
	}

	userData := &common.UserData{}
	err = ua.UserCryptor.DecodeAndDecrypt(userData, protected.WrappedKey, protected.UserData, userID.Bytes())
	if err != nil {
		return nil, err
	}

	return userData, nil
}

// LoginUser logs in a user
func (ua *UserAuthenticator) LoginUser(ctx context.Context, userID uuid.UUID, providedPassword string) (string, error) {
	// Fetch user data and check the provided credentials
	userData, err := ua.GetUserData(ctx, userID)
	if err != nil {
		return "", err
	}

	if !crypt.CompareHashAndPassword(providedPassword, userData.HashedPassword, userData.Salt) {
		return "", errors.New("Incorrect password")
	}

	// Fetch the user's groups and extract scopes
	groupDataBatch, err := ua.GetGroupDataBatch(ctx, userData.GetGroupIDs())
	if err != nil {
		return "", err
	}
	combinedScopes := common.ScopeNone
	for _, groupData := range groupDataBatch {
		combinedScopes = combinedScopes.Union(groupData.Scopes)
	}

	accessToken := NewAccessTokenDuration(userID, combinedScopes, tokenExpiryTime)
	token, err := accessToken.SerializeAccessToken(ua.TokenCryptor)
	if err != nil {
		return "", err
	}

	return token, nil
}

func (ua *UserAuthenticator) RemoveUser(ctx context.Context, userID uuid.UUID) error {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return ErrAuthStoreTxCastFailed
	}

	// Remove both the user and their group
	err := authStorageTx.RemoveUser(ctx, userID)
	if err != nil {
		return err
	}
	err = authStorageTx.RemoveGroup(ctx, userID)
	if err != nil {
		return err
	}

	return nil
}

// this function takes a user facing token and parses it into the internal
// access token format. It assumes that if the mac is valid the token information
// also is.
// TODO: this is name is bad
func (ua *UserAuthenticator) ParseAccessToken(token string) (interfaces.AccessTokenInterface, error) {
	return ParseAccessToken(ua.TokenCryptor, token)
}

// newGroup creates a group with the specified group ID and scopes
func (ua *UserAuthenticator) newGroupData(groupID uuid.UUID, scopes common.ScopeType) (*common.ProtectedGroupData, error) {
	groupData := &common.GroupData{
		Scopes: scopes,
	}
	wrappedKey, ciphertext, err := ua.GroupCryptor.EncodeAndEncrypt(groupData, groupID.Bytes())
	if err != nil {
		return nil, err
	}

	protected := &common.ProtectedGroupData{
		GroupID:    groupID,
		GroupData:  ciphertext,
		WrappedKey: wrappedKey,
	}

	return protected, nil
}

// NewGroup creates a group with the specified scopes in the authStorage
func (ua *UserAuthenticator) NewGroup(ctx context.Context, scopes common.ScopeType) (*uuid.UUID, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, ErrAuthStoreTxCastFailed
	}

	groupID, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	groupData, err := ua.newGroupData(groupID, scopes)
	if err != nil {
		return nil, err
	}

	err = authStorageTx.InsertGroup(ctx, groupData)
	if err != nil {
		return nil, err
	}

	return &groupID, nil
}

// GetGroupDataBatch fetches one or more groups' confidential data
func (ua *UserAuthenticator) GetGroupDataBatch(ctx context.Context, groupIDs []uuid.UUID) ([]common.GroupData, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		return nil, ErrAuthStoreTxCastFailed
	}

	protectedBatch, err := authStorageTx.GetGroupDataBatch(ctx, groupIDs)
	if err != nil {
		return nil, err
	}

	groupDataBatch := make([]common.GroupData, 0, len(protectedBatch))

	for _, protected := range protectedBatch {
		groupData := &common.GroupData{}
		err := ua.GroupCryptor.DecodeAndDecrypt(groupData, protected.WrappedKey, protected.GroupData, protected.GroupID.Bytes())
		if err != nil {
			return nil, err
		}

		groupDataBatch = append(groupDataBatch, *groupData)
	}

	return groupDataBatch, nil
}
