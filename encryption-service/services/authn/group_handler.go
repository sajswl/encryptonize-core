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

var ErrAuthStoreTxCastFailed = errors.New("Could not typecast authstorage to authstorage.AuthStoreInterface")

// CreateGroup creates a new group with the requested scopes.
func (a *Authn) CreateGroup(ctx context.Context, request *CreateGroupRequest) (*CreateGroupResponse, error) {
	scopes, err := common.MapScopesToScopeType(request.Scopes)
	if err != nil {
		log.Error(ctx, err, "CreateGroup: Invalid scope")
		return nil, status.Errorf(codes.InvalidArgument, "invalid scope")
	}

	groupID, err := a.UserAuthenticator.NewGroup(ctx, scopes)
	if err != nil {
		log.Error(ctx, err, "CreateGroup: Couldn't create new group")
		return nil, status.Errorf(codes.Internal, "error encountered while creating user")
	}

	return &CreateGroupResponse{
		GroupId: groupID.String(),
	}, nil
}

// AddUserToGroup adds an existing user to an existing group.
func (a *Authn) AddUserToGroup(ctx context.Context, request *AddUserToGroupRequest) (*AddUserToGroupResponse, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while adding user to group")
		log.Error(ctx, err, "AddUserToGroup: Could not typecast authstorage to AuthStoreTxInterface")
		return nil, err
	}

	userID, err := uuid.FromString(request.UserId)
	if err != nil {
		log.Errorf(ctx, err, "AddUserToGroup: Failed to parse user ID %s as UUID", request.UserId)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID")
	}

	groupID, err := uuid.FromString(request.GroupId)
	if err != nil {
		log.Errorf(ctx, err, "AddUserToGroup: Failed to parse group ID %s as UUID", request.GroupId)
		return nil, status.Errorf(codes.InvalidArgument, "invalid group ID")
	}

	// Check if the group exists
	exists, err := authStorageTx.GroupExists(ctx, groupID)
	if err != nil {
		log.Errorf(ctx, err, "AddUserToGroup: Failed to retrieve target group %v", groupID)
		return nil, status.Errorf(codes.Internal, "Failed to retrieve target group")
	}
	if !exists {
		err = status.Errorf(codes.InvalidArgument, "invalid target group ID")
		log.Errorf(ctx, err, "AddUserToGroup: Failed to retrieve target group %v", groupID)
		return nil, err
	}

	// Add group to user
	userData, err := a.UserAuthenticator.GetUserData(ctx, userID)
	if err != nil {
		log.Errorf(ctx, err, "AddUserToGroup: Failed to retrieve target user %v", userID)
		return nil, status.Errorf(codes.InvalidArgument, "Failed to retrieve target user")
	}
	userData.GroupIDs[groupID] = true
	err = a.UserAuthenticator.UpdateUser(ctx, userID, userData)
	if err != nil {
		log.Errorf(ctx, err, "AddUserToGroup: Failed to update target user %v", userID)
		return nil, status.Errorf(codes.Internal, "Failed to update target user")
	}

	// All done, commit auth changes
	if err := authStorageTx.Commit(ctx); err != nil {
		log.Error(ctx, err, "Store: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	return &AddUserToGroupResponse{}, nil
}

// RemoveUserFromGroup removes a user from a group.
func (a *Authn) RemoveUserFromGroup(ctx context.Context, request *RemoveUserFromGroupRequest) (*RemoveUserFromGroupResponse, error) {
	authStorageTx, ok := ctx.Value(common.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while adding user to group")
		log.Error(ctx, err, "RemoveUserFromGroup: Could not typecast authstorage to AuthStoreTxInterface")
		return nil, err
	}

	userID, err := uuid.FromString(request.UserId)
	if err != nil {
		log.Errorf(ctx, err, "RemoveUserFromGroup: Failed to parse user ID %s as UUID", request.UserId)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID")
	}

	groupID, err := uuid.FromString(request.GroupId)
	if err != nil {
		log.Errorf(ctx, err, "RemoveUserFromGroup: Failed to parse group ID %s as UUID", request.GroupId)
		return nil, status.Errorf(codes.InvalidArgument, "invalid group ID")
	}

	// Remove group from user
	userData, err := a.UserAuthenticator.GetUserData(ctx, userID)
	if err != nil {
		log.Errorf(ctx, err, "RemoveUserFromGroup: Failed to retrieve target user %v", userID)
		return nil, status.Errorf(codes.InvalidArgument, "Failed to retrieve target user")
	}
	delete(userData.GroupIDs, groupID)
	err = a.UserAuthenticator.UpdateUser(ctx, userID, userData)
	if err != nil {
		log.Errorf(ctx, err, "RemoveUserFromGroup: Failed to update target user %v", userID)
		return nil, status.Errorf(codes.Internal, "Failed to update target user")
	}

	// All done, commit auth changes
	if err := authStorageTx.Commit(ctx); err != nil {
		log.Error(ctx, err, "Store: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while storing object")
	}

	return &RemoveUserFromGroupResponse{}, nil
}
