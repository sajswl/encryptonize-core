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

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"syscall"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	log "encryption-service/logger"
	"encryption-service/services/authn"
	"encryption-service/services/authz"
	"encryption-service/services/enc"
	"encryption-service/services/health"
	"encryption-service/services/storage"
)

type App struct {
	StorageService    *storage.Storage
	EncryptionService *enc.Enc
	AuthnService      *authn.Authn
	AuthzService      *authz.PermissionHandler
	UnimplementedEncryptonizeServer
}

func (app *App) initgRPC(port int) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		msg := fmt.Sprintf("Failed to listen on port: %s", fmt.Sprint(port))
		log.Fatal(context.TODO(), err, msg)
	}

	// make gprc_recovery log panics and return generic errors to the caller
	recoveryOpt := grpc_recovery.WithRecoveryHandlerContext(
		func(ctx context.Context, p interface{}) error {
			stack := make([]byte, 4096)
			runtime.Stack(stack, false)
			msg := fmt.Sprintf("panic recoverd: \n\n%s\n", stack)
			log.Error(ctx, fmt.Errorf("panic: %v", p), msg)
			return status.Errorf(codes.Internal, "internal error")
		},
	)

	unaryInterceptors := []grpc.UnaryServerInterceptor{
		grpc_recovery.UnaryServerInterceptor(recoveryOpt),
		log.UnaryRequestIDInterceptor(),
		log.UnaryMethodNameInterceptor(),
		log.UnaryLogInterceptor(),
	}

	streamInterceptors := []grpc.StreamServerInterceptor{
		grpc_recovery.StreamServerInterceptor(recoveryOpt),
		log.StreamRequestIDInterceptor(),
		log.StreamMethodNameInterceptor(),
		log.StreamLogInterceptor(),
	}

	unaryInterceptors = append(unaryInterceptors, app.AuthnService.AuthStorageUnaryServerInterceptor())
	streamInterceptors = append(streamInterceptors, app.AuthnService.AuthStorageStreamingInterceptor())

	unaryInterceptors = append(unaryInterceptors, grpc_auth.UnaryServerInterceptor(app.AuthnService.CheckAccessToken))
	streamInterceptors = append(streamInterceptors, grpc_auth.StreamServerInterceptor(app.AuthnService.CheckAccessToken))

	// Add middlewares to the grpc server:
	// The order is important: AuthenticateUser needs AuthStore and Authstore needs MethodName
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(65*1024*1024),
		grpc_middleware.WithUnaryServerChain(
			unaryInterceptors...,
		),
		grpc_middleware.WithStreamServerChain(
			streamInterceptors...,
		),
	)

	storage.RegisterEncryptonizeServer(grpcServer, app.StorageService)
	enc.RegisterEncryptonizeServer(grpcServer, app.EncryptionService)
	authn.RegisterEncryptonizeServer(grpcServer, app.AuthnService)
	authz.RegisterEncryptonizeServer(grpcServer, app.AuthzService)
	RegisterEncryptonizeServer(grpcServer, app)

	// Register health checker to grpc server
	healthService := health.NewHealthChecker()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthService)

	// Register grpc reflection handler
	reflection.Register(grpcServer)

	return grpcServer, lis
}

func (app *App) StartServer() {
	ctx := context.TODO()

	// execute cli commands
	if len(os.Args) > 1 && filepath.Base(os.Args[0]) != "encryption-service.test" {
		log.Info(ctx, "Running in cli mode")

		cmd := os.Args[1]
		switch cmd {
		case "create-admin":
			msg := fmt.Sprintf("AuthenticatorInterface is of dynamic type: %v", reflect.TypeOf(app.AuthnService))
			log.Info(ctx, msg)
			if err := app.AuthnService.UserAuthenticator.NewAdminUser(app.AuthnService.AuthStore); err != nil {
				log.Fatal(ctx, err, "CreateAdminCommand")
			}
		default:
			msg := fmt.Sprintf("Invalid command: %v", cmd)
			log.Fatal(ctx, errors.New(""), msg)
		}

		return
	}

	// Setup gRPC listener
	var port = 9000
	grpcServer, lis := app.initgRPC(port)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			msg := fmt.Sprintf("Failed to serve gRPC server over port %d", port)
			log.Fatal(ctx, err, msg)
		}
	}()

	msg := fmt.Sprintf("Running gRPC API on port :%v", port)
	log.Info(ctx, msg)

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGTERM and SIGINT
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)

	log.Info(ctx, "Press CTRL + C to shutdown server")
	<-c
	log.Info(ctx, "Received shutdown signal")

	// Try to gracefully shutdown
	go func() {
		grpcServer.GracefulStop()
		close(c)
	}()

	// Wait 25 seconds, if server hasn't shut down gracefully, force it
	timeToForceShutdown := time.NewTimer(25 * time.Second)
	select {
	case <-timeToForceShutdown.C:
		log.Info(ctx, "Timeout exceeded, forcing shutdown")
		grpcServer.Stop()
	case <-c:
		// TODO should we not check if this is an repeated ctrl-c, or the channel closing?
		timeToForceShutdown.Stop()
	}

	log.Info(ctx, "Shutting down")
}
