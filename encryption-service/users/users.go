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
	ScopeDelete
	ScopeIndex
	ScopeObjectPermissions
	ScopeUserManagement
	ScopeEnd
)

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

func MapScopetypeToScopes(scope ScopeType) ([]UserScope, error) {
	userScope := []UserScope{}
	// scopes is a bitmap. This checks each bit individually
	for i := ScopeType(1); i < ScopeEnd; i <<= 1 {
		if !scope.HasScopes(i) {
			continue
		}
		switch i {
		case ScopeRead:
			userScope = append(userScope, UserScope_READ)
		case ScopeCreate:
			userScope = append(userScope, UserScope_CREATE)
		case ScopeDelete:
			userScope = append(userScope, UserScope_DELETE)
		case ScopeIndex:
			userScope = append(userScope, UserScope_INDEX)
		case ScopeObjectPermissions:
			userScope = append(userScope, UserScope_OBJECTPERMISSIONS)
		case ScopeUserManagement:
			userScope = append(userScope, UserScope_USERMANAGEMENT)
		default:
			return nil, errors.New("Invalid scopes")
		}
	}
	return userScope, nil
}
