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
package enc

import (
	"context"
)

type DisabledEnc struct {
	UnimplementedEncryptonizeServer
}

// API Enc disabled Encrypt handler
func (enc *DisabledEnc) Encrypt(ctx context.Context, request *EncryptRequest) (*EncryptResponse, error) {
	return enc.UnimplementedEncryptonizeServer.Encrypt(ctx, request)
}

// API Enc disabled Decrypt handler
func (enc *DisabledEnc) Decrypt(ctx context.Context, request *DecryptRequest) (*DecryptResponse, error) {
	return enc.UnimplementedEncryptonizeServer.Decrypt(ctx, request)
}
