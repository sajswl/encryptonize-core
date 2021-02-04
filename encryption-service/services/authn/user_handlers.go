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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	log "encryption-service/logger"
	"encryption-service/scopes"
)

// CreateUser is an exposed endpoint that enables admins to create other users
// Fails if credentials can't be generated or if the derived tag can't be stored
func (au *Authn) CreateUser(ctx context.Context, request *CreateUserRequest) (*CreateUserResponse, error) {
	usertype := scopes.ScopeNone
	for _, us := range request.UserScopes {
		switch us {
		case scopes.UserScope_READ:
			usertype |= scopes.ScopeRead
		case scopes.UserScope_CREATE:
			usertype |= scopes.ScopeCreate
		case scopes.UserScope_INDEX:
			usertype |= scopes.ScopeIndex
		case scopes.UserScope_OBJECTPERMISSIONS:
			usertype |= scopes.ScopeObjectPermissions
		case scopes.UserScope_USERMANAGEMENT:
			usertype |= scopes.ScopeUserManagement
		default:
			msg := fmt.Sprintf("CreateUser: Invalid scope %v", us)
			log.Error(ctx, msg, errors.New("CreateUser: Invalid scope"))
			return nil, status.Errorf(codes.InvalidArgument, "invalid scope")
		}
	}

	userID, token, err := au.UserAuthenticator.NewUser(ctx, usertype)
	if err != nil {
		log.Error(ctx, "CreateUser: Couldn't create new user", err)
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateUserResponse{
		UserId:      userID.String(),
		AccessToken: token,
	}, nil
}
