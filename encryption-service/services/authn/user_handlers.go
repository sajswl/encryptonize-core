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
	"context"
	"errors"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/common"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

// CreateUser is an exposed endpoint that enables admins to create other users
// Fails if credentials can't be generated or if the derived tag can't be stored
func (au *Authn) CreateUser(ctx context.Context, request *CreateUserRequest) (*CreateUserResponse, error) {
	usertype, err := common.MapScopesToScopeType(request.UserScopes)
	if err != nil {
		log.Error(ctx, errors.New("CreateUser: Invalid scope"), err.Error())
		return nil, status.Errorf(codes.InvalidArgument, "invalid scope")
	}

	userID, password, err := au.UserAuthenticator.NewUser(ctx, usertype)
	if err != nil {
		log.Error(ctx, err, "CreateUser: Couldn't create new user")
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateUserResponse{
		UserId:   userID.String(),
		Password: password,
	}, nil
}

func (au *Authn) LoginUser(ctx context.Context, request *LoginUserRequest) (*LoginUserResponse, error) {
	uuid, err := uuid.FromString(request.UserId)
	if err != nil {
		return nil, err
	}
	token, err := au.UserAuthenticator.LoginUser(ctx, uuid, request.Password)
	if err != nil {
		log.Error(ctx, err, "LoginUser: Couldn't login the user")
		return nil, status.Errorf(codes.Internal, "error encountered while logging in user")
	}

	resp := &LoginUserResponse{
		AccessToken: token,
	}
	return resp, nil
}

func (au *Authn) RemoveUser(ctx context.Context, request *RemoveUserRequest) (*RemoveUserResponse, error) {
	target, err := uuid.FromString(request.UserId)
	if err != nil {
		return nil, err
	}

	err = au.UserAuthenticator.RemoveUser(ctx, target)
	if errors.Is(err, interfaces.ErrNotFound) {
		log.Error(ctx, err, "RemoveUser: target with given UID doesn't exist")
		return nil, status.Errorf(codes.NotFound, "Target user not found")
	}
	if err != nil {
		log.Error(ctx, err, "RemoveUser: Couldn't remove the user")
		return nil, status.Errorf(codes.Internal, "error encountered while removing user")
	}

	resp := &RemoveUserResponse{}
	return resp, nil
}
