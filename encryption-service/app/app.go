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
package app

import (
	context "context"
	"encoding/hex"
	"errors"
	"io/ioutil"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"encryption-service/authn"
	"encryption-service/authstorage"
	"encryption-service/contextkeys"
	"encryption-service/crypt"
	"encryption-service/objectstorage"
)

var GitCommit string
var GitTag string

type App struct {
	Config               *Config
	MessageAuthenticator *crypt.MessageAuthenticator
	AuthStore            authstorage.AuthStoreInterface
	ObjectStore          objectstorage.ObjectStoreInterface
	UnimplementedEncryptonizeServer
}

type Config struct {
	KEK               []byte
	ASK               []byte
	AuthStorageURL    string
	ObjectStorageURL  string
	ObjectStorageID   string
	ObjectStorageKey  string
	ObjectStorageCert []byte
}

type ContextKey int

const stopSign = `
            uuuuuuuuuuuuuuuuuuuu
          u* uuuuuuuuuuuuuuuuuu *u
        u* u$$$$$$$$$$$$$$$$$$$$u *u
      u* u$$$$$$$$$$$$$$$$$$$$$$$$u *u
    u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
  u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
u* u$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$u *u
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
$ $$$* ... *$...  ...$* ... *$$$  ... *$$$ $
$ $$$u **$$$$$$$  $$$  $$$$$  $$  $$$  $$$ $
$ $$$$$$uu *$$$$  $$$  $$$$$  $$  *** u$$$ $
$ $$$**$$$  $$$$  $$$u *$$$* u$$  $$$$$$$$ $
$ $$$$....,$$$$$..$$$$$....,$$$$..$$$$$$$$ $
$ $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ $
*u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
  *u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
    *u *$$$$$$$$$$$$$$$$$$$$$$$$$$$$* u*
      *u *$$$$$$$$$$$$$$$$$$$$$$$$* u*
        *u *$$$$$$$$$$$$$$$$$$$$* u*
          *u ****************** u*
            ********************

          RUNNING IN INSECURE MODE`

func ParseConfig() (*Config, error) {
	config := &Config{}

	var KEKHex string
	var ASKHex string
	var ObjectStorageCertFromEnv string
	a := []struct {
		EnvName      string
		ConfigTarget *string
		Optional     bool
	}{
		{"KEK", &KEKHex, false},
		{"ASK", &ASKHex, false},
		{"AUTH_STORAGE_URL", &config.AuthStorageURL, false},
		{"OBJECT_STORAGE_URL", &config.ObjectStorageURL, false},
		{"OBJECT_STORAGE_ID", &config.ObjectStorageID, false},
		{"OBJECT_STORAGE_KEY", &config.ObjectStorageKey, false},
		{"OBJECT_STORAGE_CERT", &ObjectStorageCertFromEnv, false},
	}

	for _, c := range a {
		v, ok := os.LookupEnv(c.EnvName)
		if !c.Optional && !ok {
			return nil, errors.New(c.EnvName + " env missing")
		}
		*c.ConfigTarget = v
	}

	KEK, err := hex.DecodeString(KEKHex)
	if err != nil {
		return nil, errors.New("KEK env couldn't be parsed (decode hex)")
	}
	if len(KEK) != 32 {
		return nil, errors.New("KEK must be 32 bytes (64 hex digits) long")
	}
	config.KEK = KEK

	ASK, err := hex.DecodeString(ASKHex)
	if err != nil {
		return nil, errors.New("ASK env couldn't be parsed (decode hex)")
	}
	if len(ASK) != 32 {
		return nil, errors.New("ASK must be 32 bytes (64 hex digits) long")
	}
	config.ASK = ASK

	// Read object storage ID, key and certificate from file if env var not specified
	if config.ObjectStorageID == "" {
		objectStorageID, err := ioutil.ReadFile("data/object_storage_id")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_ID from file")
		}
		objectStorageKey, err := ioutil.ReadFile("data/object_storage_key")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_KEY from file")
		}
		config.ObjectStorageID = strings.TrimSpace(string(objectStorageID))
		config.ObjectStorageKey = strings.TrimSpace(string(objectStorageKey))
	}
	if ObjectStorageCertFromEnv == "" {
		objectStorageCert, err := ioutil.ReadFile("data/object_storage.crt")
		if err != nil {
			return nil, errors.New("could not read OBJECT_STORAGE_CERT from file")
		}
		config.ObjectStorageCert = objectStorageCert
	} else {
		config.ObjectStorageCert = []byte(ObjectStorageCertFromEnv)
	}

	CheckInsecure(config)

	return config, nil
}

// Prevents an accidental deployment with testing parameters
func CheckInsecure(config *Config) {
	if os.Getenv("ENCRYPTION_SERVICE_INSECURE") == "1" {
		for _, line := range strings.Split(stopSign, "\n") {
			log.Warn(line)
		}
	} else {
		if hex.EncodeToString(config.KEK) == "0000000000000000000000000000000000000000000000000000000000000000" {
			log.Fatal("Test KEK used outside of INSECURE testing mode")
		}
		if hex.EncodeToString(config.ASK) == "0000000000000000000000000000000000000000000000000000000000000001" {
			log.Fatal("Test ASK used outside of INSECURE testing mode")
		}
	}
}

// CreateAdminCommand creates a new admin users with random credentials
// This function is intended to be used for cli operation
func (app *App) CreateAdminCommand() {
	ctx := context.Background()
	authStoreTx, err := app.AuthStore.NewTransaction(ctx)
	if err != nil {
		log.Fatalf("Authstorage Begin failed: %v", err)
	}
	defer func() {
		err := authStoreTx.Rollback(ctx)
		if err != nil {
			log.Fatal(err)
		}
	}()

	ctx = context.WithValue(ctx, contextkeys.AuthStorageTxCtxKey, authStoreTx)
	adminScope := authn.ScopeUserManagement
	userID, accessToken, err := app.createUserWrapper(ctx, adminScope)
	if err != nil {
		log.Fatalf("Create user failed: %v", err)
	}

	log.Info("Created admin user:")
	log.Infof("    User ID:      %v", userID)
	log.Infof("    Access Token: %v", accessToken)
}
