package auth_errors

import (
	"path"
	"strings"

	path_helpers "github.com/moisespsena-go/path-helpers"

	"github.com/moisespsena-go/i18n-modular/i18nmod"
)

var i18ng = i18nmod.PkgToGroup(path.Dir(path_helpers.GetCalledDir()))

type err string

func (this err) Translate(ctx i18nmod.Context) string {
	return ctx.T(i18ng+".errors."+strings.ReplaceAll(string(this), " ", "_")).Get()
}

func (this err) Error() string {
	return string(this)
}

const (
	// ErrInvalidPassword invalid password error
	ErrInvalidPassword err = "invalid password"
	// ErrInvalidAccount invalid account error
	ErrInvalidAccount err = "invalid account"
	// ErrUnauthorized unauthorized error
	ErrUnauthorized err = "unauthorized"
	// ErrUidBlank uid is blank
	ErrUidBlank err = "uid blank"

	ErrMaximumNumberOfAccessesReached err = "maximum number of accesses reached"
)
