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
package enc

import (
	"context"
	"fmt"

	"github.com/gofrs/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

var NotFoundAccessObjectError = status.Errorf(codes.NotFound, "error encountered while authorizing user")

// Wraps the Authorize call
// Fails if uid or oid are wrongly formatted
// or if a user isn't authorized to edit the accessObject
func AuthorizeWrapper(ctx context.Context, accessObjectAuthenticator interfaces.AccessObjectAuthenticatorInterface, objectIDString string) (interfaces.AccessObjectInterface, error) {
	userID, ok := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthorizeWrapper: Internal error during authorization")
		log.Error(ctx, err, "Could not typecast userID to uuid.UUID")
		return nil, err
	}

	// Parse objectID from request
	objectID, err := uuid.FromString(objectIDString)
	if err != nil {
		errMsg := fmt.Sprintf("AuthorizeWrapper: Failed to parse object ID %s as UUID", objectIDString)
		log.Error(ctx, err, errMsg)
		return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	accessObject, err := accessObjectAuthenticator.FetchAccessObject(ctx, objectID)
	if err != nil {
		errMsg := fmt.Sprintf("AuthorizeWrapper: Couldn't fetch AccessObject for object %v", accessObject)
		log.Error(ctx, err, errMsg)
		return nil, NotFoundAccessObjectError
	}

	authorized := accessObject.ContainsUser(userID)
	if !authorized {
		msg := fmt.Sprintf("AuthorizeWrapper: Couldn't authorize user for object %v", accessObject)
		log.Warn(ctx, msg)
		return nil, status.Errorf(codes.PermissionDenied, "access not authorized")
	}
	return accessObject, err
}
