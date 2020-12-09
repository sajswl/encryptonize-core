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
	"encoding/hex"

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
	// Set userKind
	// authn.UserKind = 0x0
	// authn.AdminKind = 0x1
	var usertype authn.ScopeType
	switch uk := request.UserKind; uk {
	case CreateUserRequest_USER:
		usertype = authn.ScopeRead | authn.ScopeCreate | authn.ScopeIndex | authn.ScopeObjectPermissions
	case CreateUserRequest_ADMIN:
		usertype = authn.ScopeUserManagement
	default:
		log.Errorf("CreateUser: Invalid user kind %v", request.UserKind)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user type")
	}

	authStorage := ctx.Value(authStorageCtxKey).(authstorage.AuthStoreInterface)
	userID, accessToken, err := app.createUserWrapper(ctx, authStorage, usertype)
	if err != nil {
		log.Errorf("CreateUser: Couldn't create new user: %v", err)
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateUserResponse{
		UserID:      userID.String(),
		AccessToken: hex.EncodeToString(accessToken),
	}, nil
}

// createUserWrapper creates an user of specified kind with random credentials in the authStorage
func (app *App) createUserWrapper(ctx context.Context, authStorage authstorage.AuthStoreInterface, userscope authn.ScopeType) (*uuid.UUID, []byte, error) {
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, nil, err
	}

	accessToken, err := crypt.Random(32)
	if err != nil {
		return nil, nil, err
	}

	authenticator := &authn.Authenticator{
		MessageAuthenticator: app.MessageAuthenticator,
		AuthStore:            authStorage,
	}

	err = authenticator.CreateOrUpdateUser(ctx, userID, accessToken, userscope)
	if err != nil {
		return nil, nil, err
	}

	err = authStorage.Commit(ctx)
	if err != nil {
		return nil, nil, err
	}

	return &userID, accessToken, nil
}
