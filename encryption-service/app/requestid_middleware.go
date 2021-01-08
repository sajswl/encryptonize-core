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

	"encryption-service/contextkeys"
	"github.com/gofrs/uuid"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	log "github.com/sirupsen/logrus"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RequestIDUnaryInterceptor injects a request-scoped requestID which is later
// propagated to subsequent calls for tracing purposes
func RequestIDUnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID, err := uuid.NewV4()
		if err != nil {
			log.Errorf("RequestIDUnaryInterceptor: Failed to create requestID")
			return nil, status.Errorf(codes.Internal, "error encountered while creating request ID")
		}

		newCtx := context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

		return handler(newCtx, req)
	}
}

// RequestIDUnaryInterceptor injects a request-scoped requestID which is later
// propagated to subsequent calls for tracing purposes
func RequestIDStreamingInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		requestID, err := uuid.NewV4()

		if err != nil {
			log.Errorf("RequestIDStreamingInterceptor: Failed to create requestID")
			return status.Errorf(codes.Internal, "error encountered while creating request ID")
		}
		newCtx := context.WithValue(stream.Context(), contextkeys.RequestIDCtxKey, requestID)
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err = handler(srv, wrapped)

		return err
	}
}
