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
	authzimpl "encryption-service/impl/authz"
	"encryption-service/impl/crypt"
	log "encryption-service/logger"
	"encryption-service/services/app"
	"encryption-service/services/authn"
	"encryption-service/services/authz"
	"encryption-service/services/enc"
	"encryption-service/services/storage"
)

func main() {
	ctx := context.TODO()
	log.Info(ctx, "Encryption Server started")

	config, err := config.ParseConfig()
	if err != nil {
		log.Fatal(ctx, err, "Config parse failed")
	}
	log.Info(ctx, "Config parsed")

	// Setup authentication storage DB Pool connection
	authStore, err := buildtags.SetupAuthStore(context.Background(), config.AuthStorage)
	if err != nil {
		log.Fatal(ctx, err, "Authstorage connect failed")
	}
	defer authStore.Close()

	accessObjectCryptor, err := crypt.NewAESCryptor(config.Keys.AEK)
	if err != nil {
		log.Fatal(ctx, err, "NewAESCryptor (access object) failed")
	}

	tokenCryptor, err := crypt.NewAESCryptor(config.Keys.TEK)
	if err != nil {
		log.Fatal(ctx, err, "NewAESCryptor (token) failed")
	}

	userCryptor, err := crypt.NewAESCryptor(config.Keys.UEK)
	if err != nil {
		log.Fatal(ctx, err, "NewAESCryptor (user) failed")
	}

	groupCryptor, err := crypt.NewAESCryptor(config.Keys.GEK)
	if err != nil {
		log.Fatal(ctx, err, "NewAESCryptor (user) failed")
	}

	userAuthenticator := &authnimpl.UserAuthenticator{
		TokenCryptor: tokenCryptor,
		UserCryptor:  userCryptor,
		GroupCryptor: groupCryptor,
	}

	dataCryptor, err := crypt.NewAESCryptor(config.Keys.KEK)
	if err != nil {
		log.Fatal(ctx, err, "NewAESCryptor (data) failed")
	}

	authorizer := &authzimpl.Authorizer{AccessObjectCryptor: accessObjectCryptor}

	var storageService storage.EncryptonizeServer
	var encService enc.EncryptonizeServer

	if config.Features.StorageService {
		objectStore, err := buildtags.SetupObjectStore("objects", config.ObjectStorage)
		if err != nil {
			log.Fatal(ctx, err, "Objectstorage connect failed")
		}

		storageService = &storage.Storage{
			Authorizer:  authorizer,
			AuthStore:   authStore,
			ObjectStore: objectStore,
			DataCryptor: dataCryptor,
		}
		log.Info(ctx, "Storage service is enabled")
	} else {
		storageService = &storage.Disabled{}
		log.Info(ctx, "Storage service is disabled")
	}

	if config.Features.EncryptionService {
		encService = &enc.Enc{
			Authorizer:  authorizer,
			AuthStore:   authStore,
			DataCryptor: dataCryptor,
		}
		log.Info(ctx, "Encryption service is enabled")
	} else {
		encService = &enc.Disabled{}
		log.Info(ctx, "Encryption service is disabled")
	}

	authnService := &authn.Authn{
		AuthStore:         authStore,
		UserAuthenticator: userAuthenticator,
	}

	authzService := &authz.Authz{
		Authorizer:        authorizer,
		UserAuthenticator: userAuthenticator,
	}

	app := &app.App{
		StorageService:    storageService,
		EncryptionService: encService,
		AuthnService:      authnService,
		AuthzService:      authzService,
	}

	app.StartServer()
}
