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
	"fmt"

	"github.com/gofrs/uuid"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authstorage"
	"encryption-service/contextkeys"
	"encryption-service/crypt"
	log "encryption-service/logger"
)

// Authenticator represents a MessageAuthenticator used for signing and checking the access token
type Authenticator struct {
	MessageAuthenticator *crypt.MessageAuthenticator
	AuthStore            authstorage.AuthStoreInterface
	UnimplementedEncryptonizeServer
}

type AuthenticatorInterface interface {
	GRPCUnaryInterceptors() []grpc.UnaryServerInterceptor
	GRPCStreamInterceptors() []grpc.StreamServerInterceptor
	RegisterService(srv grpc.ServiceRegistrar)
	AuthenticateUser(ctx context.Context) (context.Context, error)
}

func (au Authenticator) GRPCUnaryInterceptors() []grpc.UnaryServerInterceptor {
	return []grpc.UnaryServerInterceptor{
		au.AuthStorageUnaryServerInterceptor(),
		grpc_auth.UnaryServerInterceptor(au.AuthenticateUser),
	}
}

func (au Authenticator) GRPCStreamInterceptors() []grpc.StreamServerInterceptor {
	return []grpc.StreamServerInterceptor{
		au.AuthStorageStreamingInterceptor(),
		grpc_auth.StreamServerInterceptor(au.AuthenticateUser),
	}
}

func (au Authenticator) RegisterService(srv grpc.ServiceRegistrar) {
	RegisterEncryptonizeServer(srv, au)
}

// CreateAdminCommand creates a new admin users with random credentials
// This function is intended to be used for cli operation
func (au *Authenticator) CreateAdminCommand() {
	ctx := context.Background()
	// Need to inject requestID manually, as these calls don't pass the usual middleware
	requestID, err := uuid.NewV4()
	if err != nil {
		log.Fatal(ctx, "Could not generate uuid", err)
	}
	ctx = context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

	authStoreTx, err := au.AuthStore.NewTransaction(ctx)
	if err != nil {
		log.Fatal(ctx, "Authstorage Begin failed", err)
	}
	defer func() {
		err := authStoreTx.Rollback(ctx)
		if err != nil {
			log.Fatal(ctx, "Performing rollback", err)
		}
	}()

	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTx)
	adminScope := ScopeUserManagement
	userID, accessToken, err := au.createUserWrapper(ctx, adminScope)
	if err != nil {
		log.Fatal(ctx, "Create user failed", err)
	}

	log.Info(ctx, "Created admin user:")
	log.Info(ctx, fmt.Sprintf("    User ID:      %v", userID))
	log.Info(ctx, fmt.Sprintf("    Access Token: %v", accessToken))
}

const baseAppPath string = "/app.Encryptonize/"
const baseAuthPath string = "/authn.Encryptonize/"
const healthEndpointCheck string = "/grpc.health.v1.Health/Check"
const healthEndpointWatch string = "/grpc.health.v1.Health/Watch"
const reflectionEndpoint string = "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"

var methodScopeMap = map[string]ScopeType{
	baseAuthPath + "CreateUser":      ScopeUserManagement,
	baseAppPath + "GetPermissions":   ScopeIndex,
	baseAppPath + "AddPermission":    ScopeObjectPermissions,
	baseAppPath + "RemovePermission": ScopeObjectPermissions,
	baseAppPath + "Store":            ScopeCreate,
	baseAppPath + "Retrieve":         ScopeRead,
	baseAppPath + "Version":          ScopeNone,
}

// Authenticates user using an Access Token
// the Access Token contains uid, scopes, and a random value
// this token has to be integrity protected (e.g. by an HMAC)
// this method fails if the integrity check failed or the token
// lacks the required scope
func (au Authenticator) AuthenticateUser(ctx context.Context) (context.Context, error) {
	// Grab method name
	methodName, ok := ctx.Value(contextkeys.MethodNameCtxKey).(string)
	if !ok {
		err := status.Errorf(codes.Internal, "AuthenticateUser: Internal error during authentication")
		log.Error(ctx, "Could not typecast methodName to string", err)
		return nil, err
	}

	// Don't authenticate health checks
	// IMPORTANT! This check MUST stay at the top of this function
	if methodName == healthEndpointCheck ||
		methodName == healthEndpointWatch ||
		methodName == reflectionEndpoint {
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

	if !accessToken.HasScopes(reqScope) {
		err = status.Errorf(codes.PermissionDenied, "access not authorized")
		log.Error(newCtx, "AuthenticateUser: Unauthorized access", err)
		return nil, err
	}

	log.Info(newCtx, "AuthenticateUser: User authenticated")

	return newCtx, nil
}
