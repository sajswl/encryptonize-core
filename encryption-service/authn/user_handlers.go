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
	"context"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authstorage"
	"encryption-service/contextkeys"
	log "encryption-service/logger"
)

// CreateUser is an exposed endpoint that enables admins to create other users
// Fails if credentials can't be generated or if the derived tag can't be stored
func (au Authenticator) CreateUser(ctx context.Context, request *CreateUserRequest) (*CreateUserResponse, error) {
	usertype := ScopeNone
	for _, us := range request.UserScopes {
		switch us {
		case UserScope_READ:
			usertype |= ScopeRead
		case UserScope_CREATE:
			usertype |= ScopeCreate
		case UserScope_INDEX:
			usertype |= ScopeIndex
		case UserScope_OBJECTPERMISSIONS:
			usertype |= ScopeObjectPermissions
		case UserScope_USERMANAGEMENT:
			usertype |= ScopeUserManagement
		default:
			msg := fmt.Sprintf("CreateUser: Invalid scope %v", us)
			log.Error(ctx, msg, errors.New("CreateUser: Invalid scope"))
			return nil, status.Errorf(codes.InvalidArgument, "invalid scope")
		}
	}

	userID, token, err := au.CreateUserWrapper(ctx, usertype)
	if err != nil {
		log.Error(ctx, "CreateUser: Couldn't create new user", err)
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateUserResponse{
		UserId:      userID.String(),
		AccessToken: token,
	}, nil
}

// createUserWrapper creates an user of specified kind with random credentials in the authStorage
func (au *Authenticator) CreateUserWrapper(ctx context.Context, userscope ScopeType) (*uuid.UUID, string, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(authstorage.AuthStoreTxInterface)
	if !ok {
		return nil, "", errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")
	}
	userID, err := uuid.NewV4()
	if err != nil {
		return nil, "", err
	}

	accessToken := &AccessToken{}
	err = accessToken.New(userID, userscope)
	if err != nil {
		return nil, "", err
	}

	token, err := au.SerializeAccessToken(accessToken)
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
