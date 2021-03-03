package users

import (
	"errors"

	"github.com/gofrs/uuid"
)

// ScopeType represents the different scopes a user could be granted
type ScopeType uint64

const ScopeNone ScopeType = 0
const (
	ScopeRead ScopeType = 1 << iota
	ScopeCreate
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

type UserData struct {
	UserID               uuid.UUID
	ConfidentialUserData []byte
	WrappedKey           []byte
}

type ConfidentialUserData struct {
	Password []byte
	Salt     []byte
	Scopes   ScopeType
}

func (us ScopeType) IsValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

func (us ScopeType) HasScopes(tar ScopeType) bool {
	return (us & tar) == tar
}
