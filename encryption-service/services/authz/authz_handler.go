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
package authz

import (
	"context"
	"fmt"
	"sort"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

// Retrieve a list of users who have access to the object specified in the request.
func (a *Authz) GetPermissions(ctx context.Context, request *GetPermissionsRequest) (*GetPermissionsResponse, error) {
	accessObject, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(interfaces.AccessObjectInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while getting permissions")
		log.Error(ctx, err, "GetPermissions: Could not typecast access object to AccessObjectInterface")
		return nil, err
	}

	// Grab user ids
	uids := accessObject.GetUsers()
	strUIDs := make([]string, 0, len(uids))
	for uid := range uids {
		strUIDs = append(strUIDs, uid.String())
	}
	// Make sure order of returned list is consistent
	sort.Strings(strUIDs)

	log.Info(ctx, "GetPermissions: Permissions fetched")

	return &GetPermissionsResponse{UserIds: strUIDs}, nil
}

// Grant a user access to an object.
// The requesting user has to be authorized to access the object.
func (a *Authz) AddPermission(ctx context.Context, request *AddPermissionRequest) (*AddPermissionResponse, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while adding permissions")
		log.Error(ctx, err, "AddPermission: Could not typecast authstorage to AuthStoreTxInterface")
		return nil, err
	}

	accessObject, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(interfaces.AccessObjectInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while adding permissions")
		log.Error(ctx, err, "AddPermission: Could not typecast access object to AccessObjectInterface")
		return nil, err
	}

	oid, err := uuid.FromString(request.ObjectId)
	if err != nil {
		log.Error(ctx, err, "AddPermission: Failed to parse object ID as UUID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	target, err := uuid.FromString(request.Target)
	if err != nil {
		log.Error(ctx, err, "AddPermission: Failed to parse target user ID as UUID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid target user ID")
	}

	// Check if user exists (returns error on empty rows)
	exists, err := authStorageTx.UserExists(ctx, target)

	if err != nil {
		msg := fmt.Sprintf("AddPermission: Failed to retrieve target user %v", target)
		log.Error(ctx, err, msg)

		return nil, status.Errorf(codes.Internal, "Failed to retrieve target user")
	}
	if !exists {
		msg := fmt.Sprintf("AddPermission: Failed to retrieve target user %v", target)
		err = status.Errorf(codes.InvalidArgument, "invalid target user ID")
		log.Error(ctx, err, msg)
		return nil, err
	}

	// Add the permission to the access object
	accessObject.AddUser(target)
	err = a.Authorizer.UpsertAccessObject(ctx, oid, accessObject)
	if err != nil {
		msg := fmt.Sprintf("AddPermission: Failed to add user %v to access object %v", target, oid)
		log.Error(ctx, err, msg)
		return nil, status.Errorf(codes.Internal, "error encountered while adding permission")
	}

	err = authStorageTx.Commit(ctx)
	if err != nil {
		log.Error(ctx, err, "AddPermission: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while adding permission")
	}

	ctx = context.WithValue(ctx, contextkeys.TargetIDCtxKey, target)
	log.Info(ctx, "AddPermission: Permission added")

	return &AddPermissionResponse{}, nil
}

// Remove a users access to an object.
// The requesting user has to be authorized to access the object.
func (a *Authz) RemovePermission(ctx context.Context, request *RemovePermissionRequest) (*RemovePermissionResponse, error) {
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(interfaces.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while removing permissions")
		log.Error(ctx, err, "RemovePermission: Could not typecast authstorage to AuthStoreTxInterface")
		return nil, err
	}

	accessObject, ok := ctx.Value(contextkeys.AccessObjectCtxKey).(interfaces.AccessObjectInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while removing permissions")
		log.Error(ctx, err, "RemovePermission: Could not typecast access object to AccessObjectInterface")
		return nil, err
	}

	oid, err := uuid.FromString(request.ObjectId)
	if err != nil {
		log.Error(ctx, err, "RemovePermission: Failed to parse object ID as UUID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	target, err := uuid.FromString(request.Target)
	if err != nil {
		log.Error(ctx, err, "RemovePermission: Failed to parse target user ID as UUID")
		return nil, status.Errorf(codes.InvalidArgument, "invalid target user ID")
	}

	// Add the permission to the access object
	accessObject.RemoveUser(target)
	err = a.Authorizer.UpsertAccessObject(ctx, oid, accessObject)
	if err != nil {
		msg := fmt.Sprintf("RemovePermission: Failed to remove user %v from access object %v", target, oid)
		log.Error(ctx, err, msg)
		return nil, status.Errorf(codes.Internal, "error encountered while removing permission")
	}
	err = authStorageTx.Commit(ctx)
	if err != nil {
		log.Error(ctx, err, "RemovePermission: Failed to commit auth storage transaction")
		return nil, status.Errorf(codes.Internal, "error encountered while removing permission")
	}

	ctx = context.WithValue(ctx, contextkeys.TargetIDCtxKey, target)
	log.Info(ctx, "RemovePermission: Permission removed")

	return &RemovePermissionResponse{}, nil
}
