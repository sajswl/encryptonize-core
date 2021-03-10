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

// +build !storage_mocked

package buildtags

import (
	"context"
	"encryption-service/config"
	"encryption-service/impl/authstorage"
	"encryption-service/impl/objectstorage"
	log "encryption-service/logger"
)

func SetupAuthStore(ctx context.Context, config config.AuthStorage) (*authstorage.AuthStore, error) {
	log.Info(ctx, "Setup AuthStore")
	authStore, err := authstorage.NewAuthStore(context.Background(), config.URL)
	if err != nil {
		return nil, err
	}

	// Import schema if a schema file was specified
	// TODO: is this the right place for this feature?
	if config.SchemaFile != "" {
		err = authStore.ImportSchema(ctx, config.SchemaFile)
		if err != nil {
			return nil, err
		}
	}

	return authStore, nil
}

func SetupObjectStore(bucket string, config config.ObjectStorage) (*objectstorage.ObjectStore, error) {
	log.Info(context.TODO(), "Setup ObjectStore")
	return objectstorage.NewObjectStore(config.URL, bucket, config.ID, config.Key, config.Cert)
}
