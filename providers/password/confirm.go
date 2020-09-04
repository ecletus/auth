package password

import (
	"context"
	"errors"
	"net/mail"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core/utils"
	"github.com/ecletus/mailer"
	"github.com/ecletus/session"
	"github.com/moisespsena/template/html/template"
)

var (
	// ConfirmationMailSubject confirmation mail's subject
	ConfirmationMailSubject = "Please confirm your account"

	// ConfirmedAccountFlashMessage confirmed your account message
	ConfirmedAccountFlashMessage = template.HTML("Confirmed your account!")

	// ConfirmFlashMessage confirm account flash message
	ConfirmFlashMessage = template.HTML("Please confirm your account")

	// ErrAlreadyConfirmed account already confirmed error
	ErrAlreadyConfirmed = errors.New("Your account already been confirmed")

	// ErrUnconfirmed unauthorized error
	ErrUnconfirmed = errors.New("You have to confirm your account before continuing")
)

// DefaultConfirmationMailer default confirm mailer
var DefaultConfirmationMailer = func(email string, ctx *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "confirm"
	Mailer := mailer.FromSite(ctx.Site)
	return Mailer.Send(
		&mailer.Email{
			Context: context.Background(),
			TO:      []mail.Address{{Address: email}},
			Subject: ConfirmationMailSubject,
		}, mailer.Template{
			Name:    "auth/confirmation",
			Data:    ctx,
			Context: ctx.Context,
		}.Funcs(template.FuncMap{
			"current_user": func() interface{} {
				return currentUser
			},
			"confirm_url": func() string {
				confirmURL := utils.GetAbsURL(ctx.Request)
				token, err := ctx.SessionStorer.SignedToken(claims)
				if err != nil {
					return "{TOKEN ERROR=" + err.Error() + "}"
				}
				confirmURL.Path = path.Join(ctx.Auth.AuthPath("password/confirm"), token)
				return confirmURL.String()
			},
		}))
}

// DefaultConfirmHandler default confirm handler
var DefaultConfirmHandler = func(ctx *auth.Context) error {
	var (
		authInfo    auth_identity.Basic
		provider, _ = ctx.Provider.(*Provider)
		db          = ctx.DB()
		paths       = strings.Split(ctx.Request.URL.Path, "/")
		token       = paths[len(paths)-1]
	)

	claims, err := ctx.SessionStorer.ValidateClaims(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			authInfo.Provider = provider.GetName()
			authInfo.UID = claims.Id
			authIdentity := reflect.New(utils.ModelType(ctx.Auth.Config.AuthIdentityModel)).Interface()

			if db.Where(authInfo).First(authIdentity).RecordNotFound() {
				err = auth.ErrInvalidAccount
			}

			if err == nil {
				if authInfo.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now
					if err = db.Model(authIdentity).Update(authInfo).Error; err == nil {
						ctx.SessionStorer.Flash(ctx.SessionManager(), session.Message{Message: ConfirmedAccountFlashMessage, Type: "success"})
						ctx.Auth.Redirector.Redirect(ctx.Writer, ctx.Request, "confirm")
						return nil
					}
				}
				err = ErrAlreadyConfirmed
			}
		}
	}

	return err
}
