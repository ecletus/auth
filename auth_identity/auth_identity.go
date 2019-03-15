package auth_identity

import (
	"time"

	"github.com/ecletus/auth/claims"
	"github.com/moisespsena-go/aorm"
)

type AuthIdentityInterface interface {
	SetAuthBasic(basic Basic)
	GetAuthBasic() *Basic
}

// AuthIdentity auth identity session model
type AuthIdentity struct {
	Basic
	SignLogs
}

func (au *AuthIdentity) SetAuthBasic(basic Basic) {
	au.Basic = basic
}

func (au *AuthIdentity) GetAuthBasic() *Basic {
	return &au.Basic
}

// Basic basic information about auth identity
type Basic struct {
	aorm.KeyStringSerial
	Provider          string // phone, email, wechat, github...
	UID               string `gorm:"column:uid"`
	EncryptedPassword string
	UserID            string
	ConfirmedAt       *time.Time
}

// ToClaims convert to auth Claims
func (basic Basic) ToClaims() *claims.Claims {
	claims := claims.Claims{}
	claims.Provider = basic.Provider
	claims.Id = basic.UID
	claims.UserID = basic.UserID
	return &claims
}
