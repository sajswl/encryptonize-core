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
package authn

import (
	context "context"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/crypt"
	"encryption-service/health"
	log "encryption-service/logger"
)

// AuthService represents a MessageAuthenticator used for signing and checking the access token
type AuthService struct {
	MessageAuthenticator *crypt.MessageAuthenticator
	UnimplementedEncryptonizeServer
}

type AuthServiceInterface interface {
	RegisterService(srv grpc.ServiceRegistrar)
	CheckAccessToken(ctx context.Context) (context.Context, error)
}

func (au *AuthService) RegisterService(srv grpc.ServiceRegistrar) {
	RegisterEncryptonizeServer(srv, au)
}

const baseAppPath string = "/app.Encryptonize/"
const baseAuthPath string = "/authn.Encryptonize/"

var methodScopeMap = map[string]ScopeType{
	baseAuthPath + "CreateUser":      ScopeUserManagement,
	baseAppPath + "GetPermissions":   ScopeIndex,
	baseAppPath + "AddPermission":    ScopeObjectPermissions,
	baseAppPath + "RemovePermission": ScopeObjectPermissions,
	baseAppPath + "Store":            ScopeCreate,
	baseAppPath + "Retrieve":         ScopeRead,
	baseAppPath + "Version":          ScopeNone,
}

// CheckAccessToken verifies the authenticity of a token and
// that the token contains the required scope for the requested API
// The Access Token contains uid, scopes, and a random value
// this token has to be integrity protected (e.g. by an HMAC)
func (au *AuthService) CheckAccessToken(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName, ok := ctx.Value(contextkeys.MethodNameCtxKey).(string)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthenticateUser: Internal error during authentication")
		log.Error(ctx, "Could not typecast methodName to string", err)
		return nil, err
	}

	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if methodName == health.HealthEndpointCheck || methodName == health.HealthEndpointWatch || methodName == health.ReflectionEndpoint {
		return ctx, nil
	}

	token, err := grpc_auth.AuthFromMD(ctx, "bearer")
	if err != nil {
		log.Error(ctx, "AuthenticateUser: Couldn't find token in metadata", err)
		return nil, status.Errorf(codes.InvalidArgument, "missing access token")
	}

	accessToken, err := au.ParseAccessToken(token)
	if err != nil {
		log.Error(ctx, "AuthenticateUser: Unable to parse Access Token", err)
		return nil, status.Errorf(codes.InvalidArgument, "invalid access token")
	}

	newCtx := context.WithValue(ctx, contextkeys.UserIDCtxKey, accessToken.UserID)

	reqScope, ok := methodScopeMap[methodName]
	if !ok {
		err = status.Errorf(codes.InvalidArgument, "invalid endpoint")
		log.Error(newCtx, "AuthenticateUser: Invalid Endpoint", err)
		return nil, err
	}

	if !accessToken.UserScopes.HasScopes(reqScope) {
		err = status.Errorf(codes.PermissionDenied, "access not authorized")
		log.Error(newCtx, "AuthenticateUser: Unauthorized access", err)
		return nil, err
	}

	log.Info(newCtx, "AuthenticateUser: User authenticated")

	return newCtx, nil
}
