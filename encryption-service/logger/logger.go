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
package logger

import (
	"context"
	"os"

	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"encryption-service/contextkeys"
	"encryption-service/interfaces"
)

// Initializes the global logger for uniform and structured logging
func init() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.JSONFormatter{})
	if stderrInfo, err := os.Stderr.Stat(); err == nil {
		if (stderrInfo.Mode() & os.ModeCharDevice) != 0 {
			log.SetFormatter(&log.TextFormatter{})
		}
	}
}

// Extracts logging fields from context. Does not set a field if it is not present in the context.
func fieldsFromCtx(ctx context.Context) log.Fields {
	fields := make(log.Fields)

	userID := ctx.Value(contextkeys.UserIDCtxKey)
	if userID != nil {
		fields["userId"] = userID
	}

	method := ctx.Value(contextkeys.MethodNameCtxKey)
	if method != nil {
		fields["method"] = method
	}

	requestID := ctx.Value(contextkeys.RequestIDCtxKey)
	if requestID != nil {
		fields["requestId"] = requestID
	}

	status := ctx.Value(contextkeys.StatusCtxKey)
	if status != nil {
		fields["status"] = status
	}

	objectID := ctx.Value(contextkeys.ObjectIDCtxKey)
	if objectID != nil {
		fields["objectId"] = objectID
	}

	targetID := ctx.Value(contextkeys.TargetIDCtxKey)
	if targetID != nil {
		fields["targetId"] = targetID
	}

	return fields
}

// The following functions wrap the standard logging functions
// in order to provide structured logging for our service
func Error(ctx context.Context, err error, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	fields["error"] = err
	log.WithFields(fields).Error(args...)
}

func Errorf(ctx context.Context, err error, format string, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	fields["error"] = err
	log.WithFields(fields).Errorf(format, args...)
}

func Fatal(ctx context.Context, err error, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	fields["error"] = err
	log.WithFields(fields).Fatal(args...)
}

func Fatalf(ctx context.Context, err error, format string, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	fields["error"] = err
	log.WithFields(fields).Fatalf(format, args...)
}

func Warn(ctx context.Context, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Warn(args...)
}

func Warnf(ctx context.Context, format string, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Warnf(format, args...)
}

func Info(ctx context.Context, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Info(args...)
}

func Infof(ctx context.Context, format string, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Infof(format, args...)
}

func Debug(ctx context.Context, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Debug(args...)
}

func Debugf(ctx context.Context, format string, args ...interface{}) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Debugf(format, args...)
}

// Inject full method name into unary call
func UnaryMethodNameInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		newctx := context.WithValue(ctx, contextkeys.MethodNameCtxKey, info.FullMethod)
		return handler(newctx, req)
	}
}

// UnaryObjectIDInterceptor injects the requests object ID (if any) into a unary call
func UnaryObjectIDInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		objectReq, ok := req.(interfaces.ObjectRequest)
		if !ok {
			return handler(ctx, req)
		}

		objectID, err := uuid.FromString(objectReq.GetObjectId())
		if err != nil {
			log.Error(ctx, "UnaryObjectIDInterceptor: Failed to parse objectID", err)
			return nil, status.Errorf(codes.InvalidArgument, "invalid object ID")
		}

		newctx := context.WithValue(ctx, contextkeys.ObjectIDCtxKey, objectID)
		return handler(newctx, req)
	}
}

// UnaryRequestIDInterceptor injects a request-scoped requestID which is later
// propagated to subsequent calls for tracing purposes
func UnaryRequestIDInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		requestID, err := uuid.NewV4()
		if err != nil {
			log.Error(ctx, "UnaryRequestIDInterceptor: Failed to create requestID", err)
			return nil, status.Errorf(codes.Internal, "error encountered while creating request ID")
		}

		newCtx := context.WithValue(ctx, contextkeys.RequestIDCtxKey, requestID)

		return handler(newCtx, req)
	}
}

// Logging interceptor for unary calls
func UnaryLogInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		status := "started"
		ctx = context.WithValue(ctx, contextkeys.StatusCtxKey, status)
		Info(ctx, "Request start")

		res, err := handler(ctx, req)

		status = "success"
		if err != nil {
			status = "failure"
		}
		ctx = context.WithValue(ctx, contextkeys.StatusCtxKey, status)

		Info(ctx, "Request completed")
		return res, err
	}
}
