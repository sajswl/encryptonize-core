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

	"encryption-service/app"
	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/crypt"
	log "encryption-service/logger"
	"encryption-service/objectstorage"
)

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

	authenticator := &authn.Authenticator{
		MessageAuthenticator: messageAuthenticator,
	}

	app := &app.App{
		Config:               config,
		MessageAuthenticator: messageAuthenticator,
		AuthStore:            authStore,
		Authenticator:        authenticator,
		ObjectStore:          objectStore,
		Crypter:              &crypt.AESCrypter{},
	}

	app.StartServer()
}
