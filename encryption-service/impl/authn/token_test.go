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
package authn

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/gofrs/uuid"

	"encryption-service/common"
	"encryption-service/impl/crypt"
)

var (
	TEK, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000002")
	userID = uuid.Must(uuid.FromString("00000000-0000-4000-8000-000000000002"))
	scope  = common.ScopeUserManagement
	AT     = &AccessToken{
		UserID:     userID,
		Scopes:     scope,
		ExpiryTime: time.Now().Add(time.Hour * 24 * 365 * 150),
	}

	tokenCryptor, _ = crypt.NewAESCryptor(TEK)
)

func TestSerialize(t *testing.T) {
	token, err := AT.SerializeAccessToken(tokenCryptor)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}

	t.Logf("dev admin token: %v", token)
}

func TestSerializeParse(t *testing.T) {
	// iterate over all possible scope combinations
	for s := common.ScopeType(0); s < common.ScopeEnd; s++ {
		userID := uuid.Must(uuid.NewV4())
		kek, err := crypt.Random(32)
		if err != nil {
			t.Fatalf("Random errored: %v", err)
		}

		cryptor, err := crypt.NewAESCryptor(kek)
		if err != nil {
			t.Fatalf("NewAESCryptor errored: %v", err)
		}

		accessToken := NewAccessTokenDuration(userID, s, time.Second*30)
		token, err := accessToken.SerializeAccessToken(cryptor)
		if err != nil {
			t.Fatalf("NewSerializeToken errored: %v", err)
		}

		parsedAccessToken, err := ParseAccessToken(cryptor, token)
		if err != nil {
			t.Fatalf("ParseAccessToken errored: %v", err)
		}

		if !reflect.DeepEqual(accessToken, parsedAccessToken) {
			t.Fatalf("accessToken doesn't match: %v != %v", accessToken, parsedAccessToken)
		}
	}
}

func TestParseExpiry(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	kek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	cryptor, err := crypt.NewAESCryptor(kek)
	if err != nil {
		t.Fatalf("NewAESCryptor errored: %v", err)
	}

	accessToken := NewAccessTokenDuration(userID, common.ScopeCreate, time.Second)
	token, err := accessToken.SerializeAccessToken(cryptor)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}
	_, err = ParseAccessToken(cryptor, token)
	if err != nil {
		t.Fatalf("ParseAccessToken errored: %v", err)
	}

	time.Sleep(time.Second)

	_, err = ParseAccessToken(cryptor, token)
	if err == nil || !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("ParseAccessToken should have errored: %v", err)
	}
}

func TestParseModified(t *testing.T) {
	userID := uuid.Must(uuid.NewV4())
	kek, err := crypt.Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	cryptor, err := crypt.NewAESCryptor(kek)
	if err != nil {
		t.Fatalf("NewAESCryptor errored: %v", err)
	}

	accessToken := NewAccessTokenDuration(userID, common.ScopeCreate, time.Second*30)
	token, err := accessToken.SerializeAccessToken(cryptor)
	if err != nil {
		t.Fatalf("SerializeAccessToken errored: %v", err)
	}

	tokenBytes := []byte(token)
	for i := 0; i < len(tokenBytes); i++ {
		tokenBytes[i] ^= 0xff

		_, err = ParseAccessToken(cryptor, string(tokenBytes))
		if err == nil {
			t.Fatalf("ParseAccessToken should have errored")
		}

		tokenBytes[i] ^= 0xff
	}

	kek[0] ^= 0xff
	cryptor, err = crypt.NewAESCryptor(kek)
	if err != nil {
		t.Fatalf("NewAESCryptor errored: %v", err)
	}
	_, err = ParseAccessToken(cryptor, string(tokenBytes))
	if err == nil {
		t.Fatalf("ParseAccessToken should have errored")
	}
}
