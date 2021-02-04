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
	"encryption-service/authz"
	"encryption-service/contextkeys"
	"encryption-service/crypt"
	log "encryption-service/logger"
)

// Wraps the Authorize call
// Fails if uid or oid are wrongly formatted
// or if a user isn't authorized to edit the accessObject
func AuthorizeWrapper(ctx context.Context, accessObjectMAC *crypt.MessageAuthenticator, objectIDString string) (*authz.Authorizer, *authz.AccessObject, error) {
	//Define authorizer struct
	authStorageTx, ok := ctx.Value(contextkeys.AuthStorageTxCtxKey).(authstorage.AuthStoreTxInterface)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthorizeWrapper: Internal error during authorization")
		log.Error(ctx, "Could not typecast authstorage to AuthStoreTxInterface", err)
		return nil, nil, err
	}

	authorizer := &authz.Authorizer{
		AccessObjectMAC: accessObjectMAC,
		AuthStoreTx:     authStorageTx,
	}
	userID, ok := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthorizeWrapper: Internal error during authorization")
		log.Error(ctx, "Could not typecast userID to uuid.UUID", err)
		return nil, nil, err
	}

	// Parse objectID from request
	objectID, err := uuid.FromString(objectIDString)
	if err != nil {
		errMsg := fmt.Sprintf("AuthorizeWrapper: Failed to parse object ID %s as UUID", objectIDString)
		log.Error(ctx, errMsg, err)
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	accessObject, authorized, err := authorizer.Authorize(ctx, objectID, userID)
	if err != nil {
		errMsg := fmt.Sprintf("AuthorizeWrapper: Couldn't authorize user for object %v", accessObject)
		log.Error(ctx, errMsg, err)
		return nil, nil, status.Errorf(codes.Internal, "error encountered while authorizing user")
	}

	if !authorized {
		msg := fmt.Sprintf("AuthorizeWrapper: Couldn't authorize user for object %v", accessObject)
		log.Warn(ctx, msg)
		return nil, nil, status.Errorf(codes.PermissionDenied, "access not authorized")
	}
	return authorizer, accessObject, err
}
