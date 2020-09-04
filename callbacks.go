package auth

import (
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
)

type BeforeLoginCallback = func(ctx *LoginContext) error
type InfoCallback = func(ctx *LoginContext, info *auth_identity.Basic) error
type LoggedCallback = func(ctx *LoginContext, claims *claims.Claims) error
type ErrorCallback = func(ctx *LoginContext, err error)

type LoginCallbacks struct {
	BeforeLoginCallbacks []BeforeLoginCallback
	InfoCallbacks        []InfoCallback
	LoggedCallbacks      []LoggedCallback
	ErrorCallbacks       []ErrorCallback
}

func (cb *LoginCallbacks) Before(f ...func(ctx *LoginContext) error) *LoginCallbacks {
	cb.BeforeLoginCallbacks = append(cb.BeforeLoginCallbacks, f...)
	return cb
}

func (cb *LoginCallbacks) Info(f ...func(ctx *LoginContext, info *auth_identity.Basic) error) *LoginCallbacks {
	cb.InfoCallbacks = append(cb.InfoCallbacks, f...)
	return cb
}

func (cb *LoginCallbacks) Logged(f ...func(ctx *LoginContext, claims *claims.Claims) error) *LoginCallbacks {
	cb.LoggedCallbacks = append(cb.LoggedCallbacks, f...)
	return cb
}

func (cb *LoginCallbacks) Failure(f ...func(ctx *LoginContext, err error)) *LoginCallbacks {
	cb.ErrorCallbacks = append(cb.ErrorCallbacks, f...)
	return cb
}

type AuthBeforer interface {
	BeforeAuth(ctx *LoginContext) error
}

type AuthInfor interface {
	AuthInfo(ctx *LoginContext, info *auth_identity.Basic) error
}

type AuthLoggeder interface {
	AuthLogged(ctx *LoginContext, claims *claims.Claims) error
}

type AuthFailurer interface {
	AuthFailure(ctx *LoginContext, info *auth_identity.Basic, err error)
}
