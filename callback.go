package auth

import (
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core"
)

type SignedCallbacker interface {
	Signed(ctx *core.Context, claims *claims.Claims) error
}
