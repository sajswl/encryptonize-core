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
package main

import (
	"context"

	"encryption-service/buildtags"
	"encryption-service/config"
	authnimpl "encryption-service/impl/authn"
	"encryption-service/impl/crypt"
	log "encryption-service/logger"
	"encryption-service/services/app"
	"encryption-service/services/authn"
	"encryption-service/services/enc"
)

func main() {
	ctx := context.TODO()
	log.Info(ctx, "Encryption Server started")

	config, err := config.ParseConfig()
	if err != nil {
		log.Fatal(ctx, "Config parse failed", err)
	}
	log.Info(ctx, "Config parsed")

	// Setup authentication storage DB Pool connection
	authStore, err := buildtags.SetupAuthStore(context.Background(), config.AuthStorageURL)
	if err != nil {
		log.Fatal(ctx, "Authstorage connect failed", err)
	}
	defer authStore.Close()

	accessObjectMAC, err := crypt.NewMessageAuthenticator(config.ASK, crypt.AccessObjectsDomain)
	if err != nil {
		log.Fatal(ctx, "NewMessageAuthenticator failed", err)
	}

	tokenCryptor, err := crypt.NewAESCryptor(config.TEK)
	if err != nil {
		log.Fatal(ctx, "NewAESCryptor (token) failed", err)
	}
	userAuthenticator := &authnimpl.UserAuthenticator{Cryptor: tokenCryptor}

	objectStore, err := buildtags.SetupObjectStore(
		config.ObjectStorageURL, "objects", config.ObjectStorageID, config.ObjectStorageKey, config.ObjectStorageCert,
	)
	if err != nil {
		log.Fatal(ctx, "Objectstorage connect failed", err)
	}

	dataCryptor, err := crypt.NewAESCryptor(config.KEK)
	if err != nil {
		log.Fatal(ctx, "NewAESCryptor (data) failed", err)
	}

	encService := &enc.Enc{
		AccessObjectMAC: accessObjectMAC,
		AuthStore:       authStore,
		ObjectStore:     objectStore,
		DataCryptor:     dataCryptor,
	}

	authnService := &authn.Authn{
		AuthStore:         authStore,
		UserAuthenticator: userAuthenticator,
	}

	app := &app.App{
		EncService:   encService,
		AuthnService: authnService,
	}

	app.StartServer()
}
