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
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/authz"
	"encryption-service/contextkeys"
	"encryption-service/crypt"
	log "encryption-service/logger"
)

const baseMethodPath string = "/app.Encryptonize/"
const healthEndpointCheck string = "/grpc.health.v1.Health/Check"
const healthEndpointWatch string = "/grpc.health.v1.Health/Watch"

var methodScopeMap = map[string]authn.ScopeType{
	baseMethodPath + "CreateUser":       authn.ScopeUserManagement,
	baseMethodPath + "GetPermissions":   authn.ScopeIndex,
	baseMethodPath + "AddPermission":    authn.ScopeObjectPermissions,
	baseMethodPath + "RemovePermission": authn.ScopeObjectPermissions,
	baseMethodPath + "Store":            authn.ScopeCreate,
	baseMethodPath + "Retrieve":         authn.ScopeRead,
	baseMethodPath + "Version":          authn.ScopeNone,
}

// Authenticates user using an Access Token
// the Access Token contains uid, scopes, and a random value
// this token has to be integrity protected (e.g. by an HMAC)
// this method fails if the integrity check failed or the token
// lacks the required scope
func (app *App) AuthenticateUser(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName := ctx.Value(contextkeys.MethodNameCtxKey).(string)
	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if methodName == healthEndpointCheck || methodName == healthEndpointWatch {
		return ctx, nil
	}

	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Error(ctx, "AuthenticateUser: Couldn't find token in metadata", err)
		return nil, status.Errorf(codes.InvalidArgument, "missing access token")
	}

	authenticator := &authn.Authenticator{
		MessageAuthenticator: app.MessageAuthenticator,
	}

	accessToken, err := authenticator.ParseAccessToken(token)
	if err != nil {
		log.Error(ctx, "AuthenticateUser: Unable to parse Access Token", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid access token")
	}

	newCtx := context.WithValue(ctx, contextkeys.UserIDCtxKey, accessToken.UserID)

	if !accessToken.HasScopes(methodScopeMap[methodName]) {
		err = status.Errorf(codes.PermissionDenied, "access not authorized")
		log.Error(newCtx, "AuthenticateUser: Unauthorized access", err)
		return nil, err
	}

	log.Info(newCtx, "AuthenticateUser: User authenticated")

	return newCtx, nil
}

// Wraps the Authorize call
// Fails if uid or oid are wrongly formatted
// or if a user isn't authorized to edit the accessObject
func AuthorizeWrapper(ctx context.Context, messageAuthenticator *crypt.MessageAuthenticator, objectIDString string) (*authz.Authorizer, *authz.AccessObject, error) {
	//Define authorizer struct
	authStorage := ctx.Value(contextkeys.AuthStorageCtxKey).(authstorage.AuthStoreInterface)
	authorizer := &authz.Authorizer{
		MessageAuthenticator: messageAuthenticator,
		Store:                authStorage,
	}
	userID := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)

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
