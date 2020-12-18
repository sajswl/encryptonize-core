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

	"github.com/gofrs/uuid"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
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
	baseMethodPath + "Version":          authn.ScopeNone,
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

// Authenticates user using an Access Token
// the Access Token contains uid, scopes, and a random value
// this token has to be integrity protected (e.g. by an HMAC)
// this method fails if the integrity check failed or the token
// lacks the required scope
func (app *App) AuthenticateUser(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName := ctx.Value(methodNameCtxKey).(string)
	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if methodName == healthEndpointCheck || methodName == healthEndpointWatch {
		return ctx, nil
	}

	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Errorf("AuthenticateUser: Couldn't find token in metadata, %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "missing access token")
	}

	authenticator := &authn.Authenticator{
		MessageAuthenticator: app.MessageAuthenticator,
	}

	accessToken, err := authenticator.ParseAccessToken(token)
	if err != nil {
		log.Errorf("AuthenticateUser: Unable to parse Access Token, %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid access token")
	}

	if !accessToken.HasScopes(methodScopeMap[methodName]) {
		log.Errorf("AuthenticateUser: Unauthorized access to %v by %v", methodName, accessToken)
		return nil, status.Errorf(codes.PermissionDenied, "access not authorized")
	}

	newCtx := context.WithValue(ctx, userIDCtxKey, accessToken.UserID)

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
