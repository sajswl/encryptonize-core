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

	"github.com/gofrs/uuid"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	log "encryption-service/logger"
	"encryption-service/services/health"
)

const baseAppPath string = "/app.Encryptonize/"
const baseStoragePath string = "/storage.Encryptonize/"
const baseAuthPath string = "/authn.Encryptonize/"
const baseEncPath string = "/enc.Encryptonize/"

var skippedAuthorizeMethods = map[string]bool{
	health.HealthEndpointCheck:  true,
	health.HealthEndpointWatch:  true,
	health.ReflectionEndpoint:   true,
	baseAppPath + "Version":     true,
	baseStoragePath + "Store":   true,
	baseEncPath + "Encrypt":     true,
	baseAuthPath + "LoginUser":  true,
	baseAuthPath + "CreateUser": true,
	baseAuthPath + "RemoveUser": true,
}

// AuthorizationUnaryServerInterceptor acts as authorization middleware. It expects a UID and OID to
// be in the context. It fails if the user is not authorized access to the object.
func (authz *Authz) AuthorizationUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Grab method name
		methodName, ok := ctx.Value(contextkeys.MethodNameCtxKey).(string)
		if !ok {
			err := status.Errorf(codes.Internal, "AuthenticateUser: Internal error during authentication")
			log.Error(ctx, err, "Could not typecast methodName to string")
			return nil, err
		}

		// IMPORTANT! This check MUST stay at the top of this function
		if _, ok := skippedAuthorizeMethods[methodName]; ok {
			return handler(ctx, req)
		}

		userID, ok := ctx.Value(contextkeys.UserIDCtxKey).(uuid.UUID)
		if !ok {
			err := status.Errorf(codes.Internal, "Internal error during authorization")
			log.Error(ctx, err, "Could not typecast userID to uuid.UUID")
			return nil, err
		}

		objectID, ok := ctx.Value(contextkeys.ObjectIDCtxKey).(uuid.UUID)
		if !ok {
			err := status.Errorf(codes.Internal, "Internal error during authorization")
			log.Error(ctx, err, "Could not typecast objectID to uuid.UUID")
			return nil, err
		}

		accessObject, err := authz.Authorizer.FetchAccessObject(ctx, objectID)
		if err != nil {
			log.Error(ctx, err, "Couldn't fetch AccessObject")
			return nil, status.Errorf(codes.NotFound, "error encountered while authorizing user")
		}

		authorized := accessObject.ContainsUser(userID)
		if !authorized {
			log.Warn(ctx, "Couldn't authorize user")
			return nil, status.Errorf(codes.PermissionDenied, "access not authorized")
		}

		newCtx := context.WithValue(ctx, contextkeys.AccessObjectCtxKey, accessObject)
		return handler(newCtx, req)
	}
}
