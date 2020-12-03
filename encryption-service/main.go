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
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"

	"encryption-service/app"
	"encryption-service/authstorage"
	"encryption-service/crypt"
	"encryption-service/health"
	"encryption-service/logger"
	"encryption-service/objectstorage"
)

func InitgRPC(port int, appStruct *app.App) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("Failed to listen on port: %s, error: %v", fmt.Sprint(port), err)
	}

	// Add middlewares to the grpc server:
	// The order is important: AuthenticateUser needs AuthStore and Authstore needs MethodName
	// TODO: make sure that grpc_recovery doesn't leak any infos
	grpcServer := grpc.NewServer(
		grpc_middleware.WithUnaryServerChain(
			grpc_recovery.UnaryServerInterceptor(),
			logger.UnaryServerInterceptor(),
			app.UnaryMethodNameMiddleware(),
			appStruct.AuthStorageUnaryServerInterceptor(),
			grpc_auth.UnaryServerInterceptor(appStruct.AuthenticateUser),
		),
		grpc_middleware.WithStreamServerChain(
			grpc_recovery.StreamServerInterceptor(),
			logger.StreamServerInterceptor(),
			app.StreamMethodNameMiddleware(),
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

func main() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.Info("Encryption Server started")

	config, err := app.ParseConfig()
	if err != nil {
		log.Fatalf("Config parse failed: %v", err)
	}
	log.Info("Config parsed")

	// Setup authentication storage DB Pool connection
	authDBPool, err := authstorage.ConnectDBPool(context.Background(), config.AuthStorageURL)
	if err != nil {
		log.Fatalf("Authstorage connect failed: %v", err)
	}
	defer authDBPool.Close()

	messageAuthenticator, err := crypt.NewMessageAuthenticator(config.ASK)
	if err != nil {
		log.Fatalf("NewMessageAuthenticator failed: %v", err)
	}

	objectStore, err := objectstorage.NewObjectStore(
		config.ObjectStorageURL, "objects", config.ObjectStorageID, config.ObjectStorageKey, config.ObjectStorageCert,
	)
	if err != nil {
		log.Fatalf("Objectstorage connect failed: %v", err)
	}

	app := &app.App{
		Config:               config,
		MessageAuthenticator: messageAuthenticator,
		AuthDBPool:           authDBPool,
		ObjectStore:          objectStore,
	}

	// execute cli commands
	if len(os.Args) > 1 && filepath.Base(os.Args[0]) != "main.test" {
		log.Info("Running in cli mode")

		cmd := os.Args[1]
		switch cmd {
		case "create-admin":
			app.CreateAdminCommand()
		default:
			log.Fatalf("Invalid command: %v", cmd)
		}

		return
	}

	// Setup gRPC listner
	var port int = 9000
	grpcServer, lis := InitgRPC(port, app)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC server over port %d: %v", port, err)
		}
	}()

	log.Infof("Running gRPC API on port :%v", port)

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGTERM and SIGINT
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)

	log.Info("Press CTRL + C to shutdown server")
	<-c
	log.Info("Received shutdown signal")

	// Try to gracefully shutdown
	go func() {
		grpcServer.GracefulStop()
		close(c)
	}()

	// Wait 25 seconds, if server hasn't shut down gracefully, force it
	timeToForceShutdown := time.NewTimer(25 * time.Second)
	select {
	case <-timeToForceShutdown.C:
		log.Info("Timeout exceeded, forcing shutdown")
		grpcServer.Stop()
	case <-c:
		timeToForceShutdown.Stop()
	}

	log.Info("Shutting down")
}
