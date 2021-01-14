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
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"encryption-service/app"
	"encryption-service/authstorage"
	"encryption-service/crypt"
	"encryption-service/health"
	log "encryption-service/logger"
	"encryption-service/objectstorage"
)

func InitgRPC(port int, appStruct *app.App) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		msg := fmt.Sprintf("Failed to listen on port: %s", fmt.Sprint(port))
		log.Fatal(context.TODO(), msg, err)
	}

	// Add middlewares to the grpc server:
	// The order is important: AuthenticateUser needs AuthStore and Authstore needs MethodName
	// TODO: make sure that grpc_recovery doesn't leak any infos
	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(),
			log.UnaryRequestIDInterceptor(),
			log.UnaryMethodNameInterceptor(),
			log.UnaryLogInterceptor(),
			appStruct.AuthStorageUnaryServerInterceptor(),
			grpc_auth.UnaryServerInterceptor(appStruct.AuthenticateUser),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_recovery.StreamServerInterceptor(),
			log.StreamRequestIDInterceptor(),
			log.StreamMethodNameInterceptor(),
			log.StreamLogInterceptor(),
			appStruct.AuthStorageStreamingInterceptor(),
			grpc_auth.StreamServerInterceptor(appStruct.AuthenticateUser),
		),
	)

	app.RegisterEncryptonizeServer(grpcServer, appStruct)

	// Register health checker to grpc server
	healthService := health.NewHealthChecker()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthService)

	return grpcServer, lis
}

func StartServer(appStruct *app.App) {
	ctx := context.TODO()

	// execute cli commands
	if len(os.Args) > 1 && filepath.Base(os.Args[0]) != "main.test" {
		log.Info(ctx, "Running in cli mode")

		cmd := os.Args[1]
		switch cmd {
		case "create-admin":
			appStruct.CreateAdminCommand()
		default:
			msg := fmt.Sprintf("Invalid command: %v", cmd)
			log.Fatal(ctx, msg, errors.New(""))
		}

		return
	}

	// Setup gRPC listner
	var port int = 9000
	grpcServer, lis := InitgRPC(port, appStruct)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			msg := fmt.Sprintf("Failed to serve gRPC server over port %d", port)
			log.Fatal(ctx, msg, err)
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

func main() {
	ctx := context.TODO()
	log.Info(ctx, "Encryption Server started")

	config, err := app.ParseConfig()
	if err != nil {
		log.Fatal(ctx, "Config parse failed", err)
	}
	log.Info(ctx, "Config parsed")

	// Setup authentication storage DB Pool connection
	authStore, err := authstorage.NewAuthStore(context.Background(), config.AuthStorageURL)
	if err != nil {
		log.Fatal(ctx, "Authstorage connect failed", err)
	}
	defer authStore.Close()

	messageAuthenticator, err := crypt.NewMessageAuthenticator(config.ASK)
	if err != nil {
		log.Fatal(ctx, "NewMessageAuthenticator failed", err)
	}

	objectStore, err := objectstorage.NewObjectStore(
		config.ObjectStorageURL, "objects", config.ObjectStorageID, config.ObjectStorageKey, config.ObjectStorageCert,
	)
	if err != nil {
		log.Fatal(ctx, "Objectstorage connect failed", err)
	}

	app := &app.App{
		Config:               config,
		MessageAuthenticator: messageAuthenticator,
		AuthStore:            authStore,
		ObjectStore:          objectStore,
	}

	StartServer(app)
}
