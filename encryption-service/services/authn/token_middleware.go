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
	context "context"
	"errors"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/common"
	"encryption-service/impl/authn"
	log "encryption-service/logger"
	"encryption-service/services/health"
)

const baseAppPath string = "/app.Encryptonize/"
const baseStoragePath string = "/storage.Encryptonize/"
const baseAuthPath string = "/authn.Encryptonize/"
const baseAuthzPath string = "/authz.Encryptonize/"
const baseEncPath string = "/enc.Encryptonize/"

var methodScopeMap = map[string]common.ScopeType{
	baseAuthPath + "CreateUser":        common.ScopeUserManagement,
	baseAuthPath + "RemoveUser":        common.ScopeUserManagement,
	baseAuthzPath + "GetPermissions":   common.ScopeIndex,
	baseAuthzPath + "AddPermission":    common.ScopeObjectPermissions,
	baseAuthzPath + "RemovePermission": common.ScopeObjectPermissions,
	baseStoragePath + "Store":          common.ScopeCreate,
	baseStoragePath + "Update":         common.ScopeUpdate,
	baseStoragePath + "Retrieve":       common.ScopeRead,
	baseStoragePath + "Delete":         common.ScopeDelete,
	baseEncPath + "Encrypt":            common.ScopeCreate,
	baseEncPath + "Decrypt":            common.ScopeRead,
	baseAppPath + "Version":            common.ScopeNone,
}

var skippedTokenMethods = map[string]bool{
	health.HealthEndpointCheck: true,
	health.HealthEndpointWatch: true,
	health.ReflectionEndpoint:  true,
	baseAuthPath + "LoginUser": true,
}

// CheckAccessToken verifies the authenticity of a token and
// that the token contains the required scope for the requested API
// The Access Token contains uid, scopes, and a random value
// this token has to be integrity protected (e.g. by an HMAC)
func (au *Authn) CheckAccessToken(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName, ok := ctx.Value(common.MethodNameCtxKey).(string)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthenticateUser: Internal error during authentication")
		log.Error(ctx, err, "Could not typecast methodName to string")
		return nil, err
	}

	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if _, ok := skippedTokenMethods[methodName]; ok {
		return ctx, nil
	}

	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Error(ctx, err, "AuthenticateUser: Couldn't find token in metadata")
		return nil, status.Errorf(codes.InvalidArgument, "missing access token")
	}

	accessToken, err := au.UserAuthenticator.ParseAccessToken(token)
	if errors.Is(err, authn.ErrTokenExpired) {
		log.Error(ctx, err, "AuthenticateUser: Access Token expired")
		return nil, status.Errorf(codes.Unauthenticated, "access token expired")
	}
	if err != nil {
		log.Error(ctx, err, "AuthenticateUser: Unable to parse Access Token")
		return nil, status.Errorf(codes.InvalidArgument, "invalid access token")
	}

	newCtx := context.WithValue(ctx, common.UserIDCtxKey, accessToken.GetUserID())

	reqScope, ok := methodScopeMap[methodName]
	if !ok {
		err = status.Errorf(codes.InvalidArgument, "invalid endpoint")
		log.Error(newCtx, err, "AuthenticateUser: Invalid Endpoint")
		return nil, err
	}

	if !accessToken.HasScopes(reqScope) {
		err = status.Errorf(codes.PermissionDenied, "access not authorized")
		log.Error(newCtx, err, "AuthenticateUser: Unauthorized access")
		return nil, err
	}

	log.Info(newCtx, "AuthenticateUser: User authenticated")

	return newCtx, nil
}
