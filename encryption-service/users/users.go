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

func (us ScopeType) IsValid() error {
	if us < ScopeEnd {
		return nil
	}
	return errors.New("invalid combination of scopes")
}

func (us ScopeType) HasScopes(tar ScopeType) bool {
	return (us & tar) == tar
}

func MapScopesToScopeType(scopes []UserScope) (ScopeType, error, UserScope) {
	var userScopes ScopeType
	for _, scope := range scopes {
		switch scope {
		case UserScope_READ:
			userScopes |= ScopeRead
		case UserScope_CREATE:
			userScopes |= ScopeCreate
		case UserScope_INDEX:
			userScopes |= ScopeIndex
		case UserScope_OBJECTPERMISSIONS:
			userScopes |= ScopeObjectPermissions
		case UserScope_USERMANAGEMENT:
			userScopes |= ScopeUserManagement
		default:
			return 0, errors.New("Invalid Scopes in Token"), 0
		}
	}
	return userScopes, nil, 0
}
