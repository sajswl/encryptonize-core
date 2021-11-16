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
	"encoding/json"
	"errors"
	"fmt"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/common"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

// CreateUser is an exposed endpoint that enables admins to create other users. A group with the
// same ID as the user and the requested scopes is also created.
func (au *Authn) CreateUser(ctx context.Context, request *CreateUserRequest) (*CreateUserResponse, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while creating user")
		log.Error(ctx, err, "CreateUser: Could not typecast authstorage to AuthStoreTxInterface")
		return nil, err
	}

	scopes, err := common.MapScopesToScopeType(request.Scopes)
	if err != nil {
		log.Error(ctx, errors.New("CreateUser: Invalid scope"), err.Error())
		return nil, status.Errorf(codes.InvalidArgument, "invalid scope")
	}

	userID, password, err := au.UserAuthenticator.NewUser(ctx)
	if err != nil {
		log.Error(ctx, err, "CreateUser: Couldn't create new user")
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	// Create a group for the user
	err = au.UserAuthenticator.NewGroupWithID(ctx, *userID, scopes)
	if err != nil {
		log.Error(ctx, err, "CreateUser: Couldn't create new group")
		return nil, status.Errorf(codes.Internal, "error encountered while creating group")
	}

	// Add group to user
	userData, err := au.UserAuthenticator.GetUserData(ctx, *userID)
	if err != nil {
		log.Errorf(ctx, err, "CreateUser: Failed to retrieve created user")
		return nil, status.Errorf(codes.Internal, "Failed to retrieve created user")
	}
	userData.GroupIDs[*userID] = true
	err = au.UserAuthenticator.UpdateUser(ctx, *userID, userData)
	if err != nil {
		log.Errorf(ctx, err, "CreateUser: Failed to update created user")
		return nil, status.Errorf(codes.Internal, "Failed to update created user")
	}

	if err := authStorageTx.Commit(ctx); err != nil {
		log.Error(ctx, err, "CreateUser: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateUserResponse{
		UserId:   userID.String(),
		Password: password,
	}, nil
}

// CreateCLIUser creates a new user with the requested scopes. This function is intended to be used
// for CLI operation.
func (au *Authn) CreateCLIUser(scopes string) error {
	ctx := context.Background()

	// Parse user supplied scopes
	userScopes, err := common.MapStringToScopes(scopes)
	if err != nil {
		return err
	}

	// Need to inject requestID manually, as these calls don't pass the usual middleware
	requestID, err := uuid.NewV4()
	if err != nil {
		log.Fatal(ctx, err, "Could not generate uuid")
	}
	ctx = context.WithValue(ctx, common.RequestIDCtxKey, requestID)

	authStoreTxCreate, err := au.AuthStore.NewTransaction(ctx)
	if err != nil {
		log.Fatal(ctx, err, "Authstorage Begin failed")
	}
	defer func() {
		err := authStoreTxCreate.Rollback(ctx)
		if err != nil {
			log.Fatal(ctx, err, "Performing rollback")
		}
	}()

	ctx = context.WithValue(ctx, common.AuthStorageTxCtxKey, authStoreTxCreate)
	newUser, err := au.CreateUser(ctx, &CreateUserRequest{Scopes: userScopes})
	if err != nil {
		log.Fatal(ctx, err, "CreateUser failed")
	}

	log.Info(ctx, "User created, printing to stdout")
	credentials, err := json.Marshal(
		struct {
			UserID   string `json:"user_id"`
			Password string `json:"password"`
		}{
			UserID:   newUser.UserId,
			Password: newUser.Password,
		})
	if err != nil {
		log.Fatal(ctx, err, "Create user failed")
	}
	fmt.Println(string(credentials))

	return nil
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
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while removing user")
		log.Error(ctx, err, "RemoveUser: Could not typecast authstorage to AuthStoreTxInterface")
		return nil, err
	}

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

	if err := authStorageTx.Commit(ctx); err != nil {
		log.Error(ctx, err, "RemoveUser: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while removing user")
	}

	resp := &RemoveUserResponse{}
	return resp, nil
}
