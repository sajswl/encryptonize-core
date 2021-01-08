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
	log "github.com/sirupsen/logrus"
)

func init() {
	log.SetFormatter(&log.JSONFormatter{})
}

func fieldsFromCtx(ctx context.Context) log.Fields {
	return log.Fields{
		"UserID":    ctx.Value(contextkeys.UserIDCtxKey),
		"Method":    ctx.Value(contextkeys.MethodNameCtxKey),
		"RequestID": ctx.Value(contextkeys.RequestIDCtxKey),
	}
}

func Error(ctx context.Context, msg string, err error) {
	fields := fieldsFromCtx(ctx)
	fields["Error"] = err
	log.WithFields(fields).Error(msg)
}

func Fatal(ctx context.Context, msg string, err error) {
	fields := fieldsFromCtx(ctx)
	fields["Error"] = err
	log.WithFields(fields).Fatal(msg)
}

func Warn(ctx context.Context, msg string) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Warn(msg)
}

func Info(ctx context.Context, msg string) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Info(msg)
}

func Debug(ctx context.Context, msg string) {
	fields := fieldsFromCtx(ctx)
	log.WithFields(fields).Debug(msg)
}
