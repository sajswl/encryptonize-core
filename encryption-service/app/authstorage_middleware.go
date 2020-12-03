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

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	log "github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/authstorage"
)

// AuthStorageUnaryServerInterceptor creates a DB AuthStorage instance and injects it into the context.
// It beginns a DB transcation and takes care of automatic rolling it back if needed.
func (app *App) AuthStorageUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Grab method name
		methodName := ctx.Value(methodNameCtxKey).(string)
		// Don't start DB tranaction on health checks
		// IMPORTANT! This check MUST stay at the top of this function
		if methodName == healthEndpointCheck || methodName == healthEndpointWatch {
			return handler(ctx, req)
		}

		authStorage, err := authstorage.NewDBAuthStore(ctx, app.AuthDBPool)
		if err != nil {
			log.Errorf("NewDBAuthStore failed: %v", err)
			return nil, status.Errorf(codes.Internal, "error encountered while connecting to auth storage")
		}
		defer func() {
			err := authStorage.Rollback(ctx)
			if err != nil {
				log.Error(err)
			}
		}()

		newCtx := context.WithValue(ctx, authStorageCtxKey, authStorage)
		return handler(newCtx, req)
	}
}

// AuthStorageUnaryServerInterceptor creates a DB AuthStorage instance and injects it into the context.
// It beginns a DB transcation and takes care of automatic rolling it back if needed.
func (app *App) AuthStorageStreamingInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()

		authStorage, err := authstorage.NewDBAuthStore(ctx, app.AuthDBPool)
		if err != nil {
			log.Errorf("NewDBAuthStore failed: %v", err)
			return status.Errorf(codes.Internal, "error encountered while connecting to auth storage")
		}
		defer func() {
			err := authStorage.Rollback(ctx)
			if err != nil {
				log.Error(err)
			}
		}()

		newStream := grpc_middleware.WrapServerStream(stream)
		newStream.WrappedContext = context.WithValue(ctx, authStorageCtxKey, authStorage)
		return handler(srv, newStream)
	}
}
