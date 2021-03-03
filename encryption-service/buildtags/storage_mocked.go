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

// +build storage_mocked

package buildtags

import (
	"context"
	"encryption-service/config"
	"encryption-service/impl/authstorage"
	"encryption-service/impl/objectstorage"
	"encryption-service/interfaces"
	log "encryption-service/logger"
)

func SetupAuthStore(ctx context.Context, config config.AuthStorage) (interfaces.AuthStoreInterface, error) {
	log.Info(ctx, "Setup AuthStore mocked")
	return authstorage.NewMemoryAuthStore(), nil
}

func SetupObjectStore(bucket string, config config.ObjectStorage) (interfaces.ObjectStoreInterface, error) {
	log.Info(context.TODO(), "Setup ObjectStore mocked")
	return objectstorage.NewMemoryObjectStore(), nil
}
