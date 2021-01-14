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
	"os"
	"testing"

	log "github.com/sirupsen/logrus"

	"encryption-service/app"
	"encryption-service/authstorage"
	"encryption-service/crypt"
	"encryption-service/objectstorage"
)

// Helper test function for generating code coverage of integration tests
func TestRunMain(t *testing.T) {
	main()
}

// Test function for starting the server with mock storage backends
func TestInMemoryMain(t *testing.T) {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.Info("In memory test server started")

	config, err := app.ParseConfig()
	if err != nil {
		log.Fatalf("Config parse failed: %v", err)
	}
	log.Info("Config parsed")

	messageAuthenticator, err := crypt.NewMessageAuthenticator(config.ASK)
	if err != nil {
		log.Fatalf("NewMessageAuthenticator failed: %v", err)
	}
	authDBPool := authstorage.NewMemoryAuthStore()
	objectStore := objectstorage.NewMemoryObjectStore()

	app := &app.App{
		Config:               config,
		MessageAuthenticator: messageAuthenticator,
		AuthStore:            authDBPool,
		ObjectStore:          objectStore,
	}

	StartServer(app)
}
