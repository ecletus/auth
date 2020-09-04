package auth

import "github.com/ecletus/auth/auth_errors"

const (
	ErrInvalidPassword = auth_errors.ErrInvalidPassword
	ErrInvalidAccount = auth_errors.ErrInvalidAccount
	ErrUnauthorized = auth_errors.ErrUnauthorized
	ErrUidBlank = auth_errors.ErrUidBlank
	ErrMaximumNumberOfAccessesReached = auth_errors.ErrMaximumNumberOfAccessesReached
)
