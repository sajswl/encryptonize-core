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
	"context"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	log "encryption-service/logger"
	"encryption-service/services/health"
)

// AuthStorageUnaryServerInterceptor creates a DB AuthStorage instance and injects it into the context.
// It beginns a DB transcation and takes care of automatic rolling it back if needed.
func (auth *Authn) AuthStorageUnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// Grab method name
		methodName, ok := ctx.Value(contextkeys.MethodNameCtxKey).(string)
		if !ok {
			err := status.Errorf(codes.Internal, "error encountered while connecting to auth storage")
			log.Error(ctx, err, "Could not typecast methodName to string")
			return nil, err
		}

		// Don't start DB transaction on health checks
		// IMPORTANT! This check MUST stay at the top of this function
		if methodName == health.HealthEndpointCheck || methodName == health.HealthEndpointWatch || methodName == health.ReflectionEndpoint {
			return handler(ctx, req)
		}

		authStoreTx, err := auth.AuthStore.NewTransaction(ctx)
		if err != nil {
			log.Error(ctx, err, "NewDBAuthStore failed")
			return nil, status.Errorf(codes.Internal, "error encountered while connecting to auth storage")
		}
		defer func() {
			err := authStoreTx.Rollback(ctx)
			if err != nil {
				log.Error(ctx, err, "Performing rollback")
			}
		}()

		newCtx := context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTx)
		return handler(newCtx, req)
	}
}

// AuthStorageUnaryServerInterceptor creates a DB AuthStorage instance and injects it into the context.
// It beginns a DB transcation and takes care of automatic rolling it back if needed.
func (auth *Authn) AuthStorageStreamingInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := stream.Context()

		methodName, ok := ctx.Value(contextkeys.MethodNameCtxKey).(string)
		if !ok {
			err := status.Errorf(codes.Internal, "error encountered while connecting to auth storage")
			log.Error(ctx, err, "Could not typecast methodName to string")
			return err
		}

		// Don't start DB transaction on health checks
		// IMPORTANT! This check MUST stay at the top of this function
		if methodName == health.HealthEndpointCheck || methodName == health.HealthEndpointWatch || methodName == health.ReflectionEndpoint {
			return handler(srv, stream)
		}

		authStoreTx, err := auth.AuthStore.NewTransaction(ctx)
		if err != nil {
			log.Error(ctx, err, "NewDBAuthStore failed")
			return status.Errorf(codes.Internal, "error encountered while connecting to auth storage")
		}
		defer func() {
			err := authStoreTx.Rollback(ctx)
			if err != nil {
				log.Error(ctx, err, "Performing rollback")
			}
		}()

		newStream := grpc_middleware.WrapServerStream(stream)
		newStream.WrappedContext = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTx)
		return handler(srv, newStream)
	}
}
