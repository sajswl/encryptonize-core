package users

import (
	"errors"
	"fmt"
	"time"

	"github.com/gofrs/uuid"
)

// ScopeType represents the different scopes a user could be granted
type ScopeType uint64

const ScopeNone ScopeType = 0
const (
	ScopeRead ScopeType = 1 << iota
	ScopeCreate
	ScopeUpdate
	ScopeDelete
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

type ConfidentialUserData struct {
	HashedPassword []byte
	Salt           []byte
	Scopes         ScopeType
	GroupIDs       map[uuid.UUID]bool
}

type UserData struct {
	UserID               uuid.UUID
	ConfidentialUserData []byte
	WrappedKey           []byte
	DeletedAt            *time.Time
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

func MapScopesToScopeType(scopes []UserScope) (ScopeType, error) {
	var userScopes ScopeType
	for _, scope := range scopes {
		switch scope {
		case UserScope_READ:
			userScopes |= ScopeRead
		case UserScope_CREATE:
			userScopes |= ScopeCreate
		case UserScope_UPDATE:
			userScopes |= ScopeUpdate
		case UserScope_DELETE:
			userScopes |= ScopeDelete
		case UserScope_INDEX:
			userScopes |= ScopeIndex
		case UserScope_OBJECTPERMISSIONS:
			userScopes |= ScopeObjectPermissions
		case UserScope_USERMANAGEMENT:
			userScopes |= ScopeUserManagement
		default:
			return 0, fmt.Errorf("CreateUser: Invalid scope %v", scopes)
		}
	}
	return userScopes, nil
}

func MapStringToScopeType(scopes string) (ScopeType, error) {
	var userScopes ScopeType
	for _, scope := range scopes {
		switch string(scope) {
		case "r":
			userScopes |= ScopeRead
		case "c":
			userScopes |= ScopeCreate
		case "u":
			userScopes |= ScopeUpdate
		case "d":
			userScopes |= ScopeDelete
		case "i":
			userScopes |= ScopeIndex
		case "o":
			userScopes |= ScopeObjectPermissions
		case "m":
			userScopes |= ScopeUserManagement
		default:
			return 0, fmt.Errorf("CreateUser: Invalid scope %v", string(scope))
		}
	}
	return userScopes, nil
}
