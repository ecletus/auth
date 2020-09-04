package password

import (
	"strings"

	"github.com/moisespsena-go/i18n-modular/i18nmod"
)

type err string

func (this err) Translate(ctx i18nmod.Context) string {
	return ctx.T(I18N_GROUP + ".errors." + string(this)).Get()
}

func (this err) Error() string {
	return strings.ReplaceAll(string(this), "_", " ")
}

func (this err) Cause(err error) (errs i18nmod.Errors) {
	return append(errs, this, err)
}

const (
	ErrAdminUserNotFound          err = "admin_user_not_found"
	ErrCurrentPasswordNotNatch    err = "current_password_not_match"
	ErrInvalidResetPasswordToken  err = "invalid_reset_token"
	ErrLoadAdminUserFailed        err = "load_admin_user_failed"
	ErrPasswordsNotMatch          err = "passwords_not_match"
	ErrPasswordTooWeak            err = "password_too_weak"
	ErrStrengthTestFailed         err = "strength_test_failed"
	ErrUserIdentityCreationFailed err = "user_identity_creation_failed"
)
