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
package crypt

import (
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// MessageAuthenticator encapsulates a symmetric key used for tagging msgs and verifying msgs + tags
type MessageAuthenticator struct {
	domainKey []byte
}

// MessageAuthenticatorDomainType represents the different tagging Domains of the MessageAuthenticator
type MessageAuthenticatorDomainType uint64

const (
	UsersDomain MessageAuthenticatorDomainType = iota
	AccessObjectsDomain
	TokenDomain
	DomainLimit
)

// NewMessageAuthenticator creates a new MessageAuthenticator and derives the corresponding domain key
func NewMessageAuthenticator(ask []byte, domain MessageAuthenticatorDomainType) (*MessageAuthenticator, error) {
	if len(ask) != 32 {
		return nil, errors.New("invalid ASK size")
	}
	if domain >= DomainLimit {
		return nil, errors.New("invalid MessageAuthenticator Domain")
	}

	domainKey, err := deriveDomainKey(ask, domain)
	if err != nil {
		return nil, err
	}

	return &MessageAuthenticator{
		domainKey: domainKey,
	}, nil
}

// deriveDomainKey derives a domain separated key for an ASK + MessageAuthenticatorDomain using HKDF from RFC 5869 / NIST SP 800-56C
func deriveDomainKey(ask []byte, MessageAuthenticatorDomain MessageAuthenticatorDomainType) ([]byte, error) {
	info := make([]byte, 8)
	binary.LittleEndian.PutUint64(info, uint64(MessageAuthenticatorDomain))

	hkdf := hkdf.New(sha3.New256, ask, nil, info)
	key := make([]byte, 32)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// Tag returns a tag for the msg
func (s *MessageAuthenticator) Tag(msg []byte) ([]byte, error) {
	h := NewKMAC256(s.domainKey, 32, nil)
	_, err := h.Write(msg)
	if err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}

// Verify returns if a msg and its tags are valid
func (s *MessageAuthenticator) Verify(msg, msgTag []byte) (bool, error) {
	calcTag, err := s.Tag(msg)
	if err != nil {
		return false, err
	}

	return hmac.Equal(msgTag, calcTag), nil
}
