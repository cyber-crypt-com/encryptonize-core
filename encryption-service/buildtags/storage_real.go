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
	"encryption-service/impl/authstorage"
	"encryption-service/impl/objectstorage"
	log "encryption-service/logger"
)

func SetupAuthStore(ctx context.Context, URL string) (*authstorage.AuthStore, error) {
	log.Info(ctx, "Setup AuthStore")
	return authstorage.NewAuthStore(context.Background(), URL)
}

func SetupObjectStore(endpoint, bucket, accessID, accessKey string, cert []byte) (*objectstorage.ObjectStore, error) {
	log.Info(context.TODO(), "Setup ObjectStore")
	return objectstorage.NewObjectStore(endpoint, bucket, accessID, accessKey, cert)
}
