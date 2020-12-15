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
package app

import (
	"context"

	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/crypt"
)

// CreateUser is an exposed endpoint that enables admins to create other users
// Fails if credentials can't be generated or if the derived tag can't be stored
func (app *App) CreateUser(ctx context.Context, request *CreateUserRequest) (*CreateUserResponse, error) {
	usertype := authn.ScopeNone
	for _, us := range request.UserScopes {
		switch us {
		case CreateUserRequest_READ:
			usertype |= authn.ScopeRead
		case CreateUserRequest_CREATE:
			usertype |= authn.ScopeCreate
		case CreateUserRequest_INDEX:
			usertype |= authn.ScopeIndex
		case CreateUserRequest_OBJECTPERMISSIONS:
			usertype |= authn.ScopeObjectPermissions
		case CreateUserRequest_USERMANAGEMENT:
			usertype |= authn.ScopeUserManagement
		default:
			log.Errorf("CreateUser: Invalid scope %v", us)
			return nil, status.Errorf(codes.InvalidArgument, "invalid scope")
		}
	}

	userID, token, err := app.createUserWrapper(ctx, usertype)
	if err != nil {
		log.Errorf("CreateUser: Couldn't create new user: %v", err)
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateUserResponse{
		UserId:      userID.String(),
		AccessToken: token,
	}, nil
}

// createUserWrapper creates an user of specified kind with random credentials in the authStorage
func (app *App) createUserWrapper(ctx context.Context, userscope authn.ScopeType) (*uuid.UUID, string, error) {
	authStorage := ctx.Value(authStorageCtxKey).(authstorage.AuthStoreInterface)

	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	nonce, err := crypt.Random(16)
	if err != nil {
		return nil, "", err
	}

	authenticator := &authn.Authenticator{
		MessageAuthenticator: app.MessageAuthenticator,
	}

	accessToken := &authn.AccessToken{}
	err = accessToken.New(userID, userscope)
	if err != nil {
		return nil, "", err
	}

	token, err := authenticator.SerializeAccessToken(accessToken, nonce)
	if err != nil {
		return nil, "", err
	}

	token = "bearer " + token

	// insert user for compatibility with the check in permissions_handler
	// we only need to know if a user exists there, thus it is only important
	// that a row exists
	err = authStorage.UpsertUser(ctx, userID, []byte{})
	if err != nil {
		return nil, "", err
	}

	err = authStorage.Commit(ctx)
	if err != nil {
		return nil, "", err
	}

	return &userID, token, nil
}
