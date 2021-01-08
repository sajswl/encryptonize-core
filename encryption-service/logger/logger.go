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
package logger

import (
	"context"

	"encryption-service/contextkeys"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/grpc-ecosystem/go-grpc-middleware/util/metautils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Logging interceptor for unary calls
func UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		userID := metautils.ExtractIncoming(ctx).Get("userID")
		requestID := ctx.Value(contextkeys.RequestIDCtxKey)

		log.WithFields(log.Fields{
			"UserID":    userID,
			"Method":    info.FullMethod,
			"Status":    "request",
			"RequestID": requestID,
		}).Info("Request start")

		res, err := handler(ctx, req)

		status := "success"
		if err != nil {
			status = "failure"
		}

		log.WithFields(log.Fields{
			"UserID":    userID,
			"Method":    info.FullMethod,
			"Status":    status,
			"RequestID": requestID,
		}).Info("Request completed")

		return res, err
	}
}

// Logging interceptor for stream calls
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		log.Infof("srv: %v, stream: %v, info: %v", srv, stream, info)

		var newCtx context.Context
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		err := handler(srv, wrapped)

		return err
	}
}
