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
package authn

import (
	"encryption-service/interfaces"
)

// AuthnService represents a MessageAuthenticator used for signing and checking the access token
type AuthnService struct {
	AuthStore         interfaces.AuthStoreInterface
	UserAuthenticator interfaces.UserAuthenticatorInterface
	UnimplementedEncryptonizeServer
}
