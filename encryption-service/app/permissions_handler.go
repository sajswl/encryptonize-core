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
	"fmt"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authstorage"
	"encryption-service/contextkeys"
	log "encryption-service/logger"
)

// Retrieve a list of users who have access to the object specified in the request.
func (app *App) GetPermissions(ctx context.Context, request *GetPermissionsRequest) (*GetPermissionsResponse, error) {
	_, accessObject, err := AuthorizeWrapper(ctx, app.MessageAuthenticator, request.ObjectId)
	if err != nil {
		// AuthorizeWrapper logs and generates user facing error, just pass it on here
		return nil, err
	}

	// Parse objectID from request
	oid, err := uuid.FromString(request.ObjectId)
	if err != nil {
		log.Error(ctx, "GetPermissions: Failed to parse object ID as UUID", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	// Grab user ids
	uids, err := accessObject.MakeUIDStringList()
	if err != nil {
		msg := fmt.Sprintf("GetPermissions: Couldn't parse access object for ID %v", oid)
		log.Error(ctx, msg, err)
		return nil, status.Errorf(codes.Internal, "error encountered while getting permissions")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, request.ObjectId)
	log.Info(ctx, "GetPermissions: Permission added")

	return &GetPermissionsResponse{UserIds: uids}, nil
}

// Grant a user access to an object.
// The requesting user has to be authorized to access the object.
func (app *App) AddPermission(ctx context.Context, request *AddPermissionRequest) (*AddPermissionResponse, error) {
	authStorage, ok := ctx.Value(contextkeys.AuthStorageCtxKey).(authstorage.AuthStoreInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while adding permissions")
		log.Error(ctx, "AddPermission: Could not parse authStorage from context", err)

		return nil, err
	}

	authorizer, accessObject, err := AuthorizeWrapper(ctx, app.MessageAuthenticator, request.ObjectId)
	if err != nil {
		// AuthorizeWrapper logs and generates user facing error, just pass it on here
		return nil, err
	}

	oid, err := uuid.FromString(request.ObjectId)
	if err != nil {
		log.Error(ctx, "AddPermission: Failed to parse object ID as UUID", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	target, err := uuid.FromString(request.Target)
	if err != nil {
		log.Error(ctx, "AddPermission: Failed to parse target user ID as UUID", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid target user ID")
	}

	// Check if user exists (returns error on empty rows)
	_, err = authStorage.GetUserTag(ctx, target)
	if err != nil {
		msg := fmt.Sprintf("AddPermission: Failed to retrieve target user %v", target)
		log.Error(ctx, msg, err)

		if err == authstorage.ErrNoRows {
			return nil, status.Errorf(codes.InvalidArgument, "invalid target user ID")
		}
		return nil, status.Errorf(codes.Internal, "Failed to retrieve target user")
	}

	// Add the permission to the access object
	err = authorizer.AddPermission(ctx, accessObject, oid, target)
	if err != nil {
		msg := fmt.Sprintf("AddPermission: Failed to add user %v to access object %v", target, oid)
		log.Error(ctx, msg, err)
		return nil, status.Errorf(codes.Internal, "error encountered while adding permission")
	}

	err = authStorage.Commit(ctx)
	if err != nil {
		log.Error(ctx, "AddPermission: Failed to commit auth storage transaction", err)
		return nil, status.Errorf(codes.Internal, "error encountered while adding permission")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, oid)
	ctx = context.WithValue(ctx, contextkeys.TargetIDCtxKey, target)
	log.Info(ctx, "AddPermission: Permission added")

	return &AddPermissionResponse{}, nil
}

// Remove a users access to an object.
// The requesting user has to be authorized to access the object.
func (app *App) RemovePermission(ctx context.Context, request *RemovePermissionRequest) (*RemovePermissionResponse, error) {
	authStorage, ok := ctx.Value(contextkeys.AuthStorageCtxKey).(authstorage.AuthStoreInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "error encountered while removing permissions")
		log.Error(ctx, "RemovePermission: Could not parse authStorage from context", err)

		return nil, err
	}

	authorizer, accessObject, err := AuthorizeWrapper(ctx, app.MessageAuthenticator, request.ObjectId)
	if err != nil {
		// AuthorizeWrapper logs and generates user facing error, just pass it on here
		return nil, err
	}

	oid, err := uuid.FromString(request.ObjectId)
	if err != nil {
		log.Error(ctx, "RemovePermission: Failed to parse object ID as UUID", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	target, err := uuid.FromString(request.Target)
	if err != nil {
		log.Error(ctx, "RemovePermission: Failed to parse target user ID as UUID", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid target user ID")
	}

	// Add the permission to the access object
	err = authorizer.RemovePermission(ctx, accessObject, oid, target)
	if err != nil {
		msg := fmt.Sprintf("RemovePermission: Failed to remove user %v from access object %v", target, oid)
		log.Error(ctx, msg, err)
		return nil, status.Errorf(codes.Internal, "error encountered while removing permission")
	}
	err = authStorage.Commit(ctx)
	if err != nil {
		log.Error(ctx, "RemovePermission: Failed to commit auth storage transaction", err)
		return nil, status.Errorf(codes.Internal, "error encountered while removing permission")
	}

	ctx = context.WithValue(ctx, contextkeys.ObjectIDCtxKey, oid)
	ctx = context.WithValue(ctx, contextkeys.TargetIDCtxKey, target)
	log.Info(ctx, "RemovePermission: Permission removed")

	return &RemovePermissionResponse{}, nil
}
