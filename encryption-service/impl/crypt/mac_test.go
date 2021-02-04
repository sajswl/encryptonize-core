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
package crypt

import (
	"crypto/hmac"
	"encoding/hex"
	"testing"
)

/* Generated with:

key=$(php -r '
$ask = "28855c7efc8532d92567300933cc1ca2d0586f55dcc9f054fcca2f05254fbf7f";
$domain = 1;
echo bin2hex(hash_hkdf("sha3-256", hex2bin($ask), 32, pack("P", $domain)))."\n";')

node -e "
msg = Buffer.from('9c09207ff0e6e582cb3747dca954c94d45c05e93f1e6f21179cf0e25b4cede74b5479d32f5166935c86f0441905865', 'hex')
key = Buffer.from('$key', 'hex')

kmac256 = require('js-sha3').kmac256
console.log(kmac256(key, msg, 256, ''))"

*/
var (
	ASK, _                     = hex.DecodeString("28855c7efc8532d92567300933cc1ca2d0586f55dcc9f054fcca2f05254fbf7f")
	MessageAuthenticatorDomain = AccessObjectsDomain
	msg, _                     = hex.DecodeString("9c09207ff0e6e582cb3747dca954c94d45c05e93f1e6f21179cf0e25b4cede74b5479d32f5166935c86f0441905865")
	expectedTag, _             = hex.DecodeString("4a8daa2f8ca13f132499a122117df158522e814585bf511098c4c6be1b6d7600")
)

func TestMessageAuthenticator(t *testing.T) {
	s, err := NewMessageAuthenticator(ASK, MessageAuthenticatorDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	msg, err := Random(32)
	if err != nil {
		t.Fatalf("Random errored: %v", err)
	}

	tag, err := s.Tag(msg)
	if err != nil {
		t.Fatalf("Tag errored: %v", err)
	}

	ok, err := s.Verify(msg, tag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if !ok {
		t.Error("Verify should have returned ok")
	}
}

func TestTag(t *testing.T) {
	s, err := NewMessageAuthenticator(ASK, MessageAuthenticatorDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	got, err := s.Tag(msg)
	if err != nil {
		t.Fatalf("Tag errored: %v", err)
	}

	if !hmac.Equal(expectedTag, got) {
		t.Errorf("Tag doesn't match: %x != %x", expectedTag, got)
	}
}

func TestInvalidASK(t *testing.T) {
	_, err := NewMessageAuthenticator(ASK[1:], MessageAuthenticatorDomain)
	if err == nil || err.Error() != "invalid ASK size" {
		t.Error("Sign should have errored")
	}
}

func TestInvalidDomain(t *testing.T) {
	maxUint64 := ^uint64(0)
	_, err := NewMessageAuthenticator(ASK, MessageAuthenticatorDomainType(maxUint64))
	if err == nil || err.Error() != "invalid MessageAuthenticator Domain" {
		t.Error("NewMessageAuthenticator should have errored")
	}
}

func TestVerify(t *testing.T) {
	s, err := NewMessageAuthenticator(ASK, MessageAuthenticatorDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	valid, err := s.Verify(msg, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if !valid {
		t.Errorf("Verify should have returned valid")
	}
}

func TestVerifyModifiedASK(t *testing.T) {
	ASKmodified, _ := hex.DecodeString("28855c7efc8532d92567300933cc1ca2d0586f55dcc9f054fcca2f05254fbf7e")
	s, err := NewMessageAuthenticator(ASKmodified, MessageAuthenticatorDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	valid, err := s.Verify(msg, expectedTag)

	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifiedMsg(t *testing.T) {
	s, err := NewMessageAuthenticator(ASK, MessageAuthenticatorDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	valid, err := s.Verify(append(msg, 0), expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifiedDomain(t *testing.T) {
	s, err := NewMessageAuthenticator(ASK, TokenDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	valid, err := s.Verify(msg, expectedTag)
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

func TestVerifyModifiedMAC(t *testing.T) {
	s, err := NewMessageAuthenticator(ASK, MessageAuthenticatorDomain)
	if err != nil {
		t.Fatalf("NewMessageAuthenticator errored: %v", err)
	}

	valid, err := s.Verify(msg, append(expectedTag, 0))
	if err != nil {
		t.Fatalf("Verify errored: %v", err)
	}

	if valid {
		t.Errorf("Verify should have returned invalid")
	}
}

/* Generated with:

php -r '
$ask = "8d72db770d98989e898a5768b644a4fc990e11e8f13b02ed3ead3b0a3a69e5fa";
$domain = 0x1234567890abcdef;
echo bin2hex(hash_hkdf("sha3-256", hex2bin($ask), 32, pack("P", $domain)))."\n";'

*/
func TestDeriveDomainKey(t *testing.T) {
	ask, _ := hex.DecodeString("8d72db770d98989e898a5768b644a4fc990e11e8f13b02ed3ead3b0a3a69e5fa")
	domain := MessageAuthenticatorDomainType(0x1234567890abcdef)
	expectedKey, _ := hex.DecodeString("c45a6118f74edda88d3c725e919330f5faf99413a3f772cb1f9e9661005695c5")

	key, err := deriveDomainKey(ask, domain)
	if err != nil {
		t.Fatalf("deriveDomainKey errored: %v", err)
	}

	if !hmac.Equal(expectedKey, key) {
		t.Errorf("Key doesn't match: %x != %x", expectedKey, key)
	}
}
