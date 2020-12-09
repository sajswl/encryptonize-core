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
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/gofrs/uuid"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/authz"
	"encryption-service/crypt"
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
}

// Inject full method name into unary call
func UnaryMethodNameMiddleware() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		newctx := context.WithValue(ctx, methodNameCtxKey, info.FullMethod)
		return handler(newctx, req)
	}
}

// Inject full method name into stream call
func StreamMethodNameMiddleware() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		newCtx := context.WithValue(stream.Context(), methodNameCtxKey, info.FullMethod)
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err := handler(srv, wrapped)

		return err
	}
}

// Authenticates user against auth storage
// This function assumes that user credentials are stored in context metadata
// Only if the user is found in the auth storage and the user and tag match will the user be authenticated
// Otherwise this function will fail
func (app *App) AuthenticateUser(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName := ctx.Value(methodNameCtxKey).(string)
	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if methodName == healthEndpointCheck || methodName == healthEndpointWatch {
		return ctx, nil
	}

	// Extract user id from context and parse it into uuid type
	userIDString := metautils.ExtractIncoming(ctx).Get("userID")
	if len(userIDString) == 0 {
		log.Errorf("AuthenticateUser: Couldn't find user ID in metadata")
		return nil, status.Errorf(codes.InvalidArgument, "missing user ID")
	}
	userID, err := uuid.FromString(userIDString)
	if err != nil {
		log.Errorf("AuthenticateUser: Failed to parse user ID as UUID, %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID")
	}
	// for now, also extract the scopes
	// they will be moved into the token at a later point in time
	var userScopes authn.ScopeType
	userScopesString := metautils.ExtractIncoming(ctx).Get("userScopes")
	if len(userScopesString) == 0 {
		log.Errorf("AuthenticateUser: Couldn't find user sopes in metadata")
		return nil, status.Errorf(codes.InvalidArgument, "missing scopes")
	}
	userScopesInt, err := strconv.ParseUint(userScopesString, 10, 64)
	if err != nil {
		log.Errorf("AuthenticateUser: Failed to parse scopes as uint64")
		return nil, status.Errorf(codes.InvalidArgument, "invalid scopes")
	}
	userScopes = authn.ScopeType(userScopesInt)
	if userScopes.IsValid() != nil {
		log.Errorf("AuthenticateUser: Invalid scopes value")
		return nil, status.Errorf(codes.InvalidArgument, "invalid scopes")
	}

	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Errorf("AuthenticateUser: Couldn't find token in metadata, %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "missing access token")
	}
	byteToken, err := hex.DecodeString(token)
	if err != nil {
		log.Errorf("AuthenticateUser: Failed to decode token, %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid access token")
	}

	// fetch the required scopes for that endpoint
	// this is done early to prevent the database being querried over invalid requests
	requiredScope, ok := methodScopeMap[methodName]
	if !ok {
		log.Errorf("AuthenticateUser: Unrecognized endpoint called, %v", methodName)
		return nil, status.Errorf(codes.InvalidArgument, "invalid method called")
	}

	// check scopes now to prevent unnecessary database querries this check
	// supports cases where one endpoint would require multiple scopes
	// Security Considerations:
	// 	1. We cannot trust that check until we performed the "login"
	//  2. an attacker changing the scopes could make the server respond with
	//     "Unauthorized" to arbitrary requests. Such attacker could also
	//     drop the request and outright forge the response
	if (requiredScope & userScopes) != requiredScope {
		log.Errorf("AuthenticateUser: User is not authorized to use the endpoint")
		return nil, status.Errorf(codes.PermissionDenied, "access not authorized")
	}

	authStorage := ctx.Value(authStorageCtxKey).(authstorage.AuthStoreInterface)
	authenticator := &authn.Authenticator{
		MessageAuthenticator: app.MessageAuthenticator,
		AuthStore:            authStorage,
	}

	authenticated, err := authenticator.LoginUser(ctx, userID, byteToken, userScopes)
	if errors.Is(err, authstorage.ErrNoRows) {
		log.Errorf("AuthenticateUser: User %v not found: %v", userID, err)
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}
	if err != nil {
		log.Errorf("AuthenticateUser: Couldn't authenticate user %v, encountered error: %v", userID, err)
		return nil, status.Errorf(codes.Internal, "error encountered while authenticating user")
	}
	if !authenticated {
		log.Errorf("AuthenticateUser: Couldn't authenticate user %v, %v", userID, err)
		return nil, status.Errorf(codes.Unauthenticated, "user not authenticated")
	}
	// we checked the required scopes earlier and by confirming these through the login
	// we can retroactively trust that check

	newCtx := context.WithValue(ctx, userIDCtxKey, userID)

	return newCtx, nil
}

// Wraps the Authorize call
// Fails if uid or oid are wrongly formatted
// or if a user isn't authorized to edit the accessObject
func AuthorizeWrapper(ctx context.Context, messageAuthenticator *crypt.MessageAuthenticator, objectIDString string) (*authz.Authorizer, *authz.AccessObject, error) {
	//Define authorizer struct
	authStorage := ctx.Value(authStorageCtxKey).(authstorage.AuthStoreInterface)
	authorizer := &authz.Authorizer{
		MessageAuthenticator: messageAuthenticator,
		Store:                authStorage,
	}
	userID := ctx.Value(userIDCtxKey).(uuid.UUID)

	// Parse objectID from request
	objectID, err := uuid.FromString(objectIDString)
	if err != nil {
		log.Errorf("AuthorizeWrapper: Failed to parse object ID as UUID: %v", err)
		return nil, nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
	}

	accessObject, authorized, err := authorizer.Authorize(ctx, objectID, userID)
	if err != nil {
		log.Errorf("AuthorizeWrapper: Couldn't authorize user %v for object %v, encountered error: %v", userID, objectID, err)
		return nil, nil, status.Errorf(codes.Internal, "error encountered while authorizing user")
	}

	if !authorized {
		log.Errorf("AuthorizeWrapper: Couldn't authorize user %v for object %v, encountered error: %v", userID, objectID, err)
		return nil, nil, status.Errorf(codes.PermissionDenied, "access not authorized")
	}
	return authorizer, accessObject, err
}
