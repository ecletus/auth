package auth_identity

import (
	"reflect"
	"time"

	"github.com/ecletus/auth/auth_errors"

	"github.com/ecletus/core"

	"github.com/ecletus/core/utils"

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

func (AuthIdentity) AormNonFieldStructor() {
}

func (au AuthIdentity) Signed(ctx *core.Context, claims *claims.Claims) (err error) {
	DB := ctx.DB()
	scope := DB.NewScope(au)
	if err = DB.Model(au).Select("sign_count, limit_access").First(&au, "uid = ?", claims.Id).Error; err != nil {
		return
	}

	if au.LimitAccess > 0 && au.SignCount+1 >= au.LimitAccess {
		return auth_errors.ErrMaximumNumberOfAccessesReached
	}

	return DB.Table(scope.QuotedTableName()).Exec("UPDATE "+scope.QuotedTableName()+" SET sign_count = (sign_count+1), last_login_at = ? WHERE uid = ?", claims.LastLoginAt, claims.Id).Error
}

func (au *AuthIdentity) SetAuthBasic(basic Basic) {
	au.Basic = basic
}

func (au *AuthIdentity) GetAuthBasic() *Basic {
	return &au.Basic
}

// Basic basic information about auth identity
type Basic struct {
	aorm.Model
	Provider          string // phone, email, wechat, github...
	UID               string `sql:"column:uid;unique"`
	EncryptedPassword string
	UserID            string
	ConfirmedAt       *time.Time
	ExpireAt          *time.Time
	LastLoginAt       *time.Time
	IsAdmin           bool
	LimitAccess       uint64 `sql:"not null;default:0"`
	SignCount         uint64 `sql:"not null;default:0"`
}

// ToClaims convert to auth Claims
func (basic Basic) ToClaims() *claims.Claims {
	Claims := claims.Claims{
		Provider: basic.Provider,
		UserID:   basic.UserID,
		IsAdmin:  basic.IsAdmin,
	}
	Claims.Id = basic.UID
	Claims.IssuedAt = basic.ID.Time().UTC().Unix()
	if basic.ExpireAt != nil {
		Claims.ExpiresAt = basic.ExpireAt.UTC().Unix()
	}
	return &Claims
}

func NewIdentityInterface(identityModel interface{}) AuthIdentityInterface {
	return reflect.New(utils.ModelType(identityModel)).Interface().(AuthIdentityInterface)
}
