package password

import (
	"net/mail"
	"path"
	"reflect"
	"strings"
	"time"

	"errors"
	"fmt"

	"github.com/moisespsena-go/zxcvbn-fb"
	"github.com/moisespsena/template/html/template"
	"github.com/aghape/auth"
	"github.com/aghape/auth/auth_identity"
	"github.com/aghape/auth/claims"
	"github.com/aghape/mailer"
	"github.com/aghape/aghape/utils"
	"github.com/aghape/session"
	"golang.org/x/crypto/bcrypt"
)

var (
	// ResetPasswordMailSubject reset password mail's subject
	ResetPasswordMailSubject = "Reset your password"

	// SendChangePasswordMailFlashMessage send change password mail flash message
	SendChangePasswordMailFlashMessage = template.HTML("You will receive an email with instructions on how to reset your password in a few minutes")

	// ChangedPasswordFlashMessage changed password success flash message
	ChangedPasswordFlashMessage = template.HTML("Changed your password!")
)

// DefaultResetPasswordMailer default reset password mailer
var DefaultResetPasswordMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "reset_password"

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			Subject: ResetPasswordMailSubject,
		}, mailer.Template{
			Name:    "auth/reset_password",
			Data:    context,
			Context: context.Context,
		}.Funcs(template.FuncMap{
			"current_user": func() interface{} {
				return currentUser
			},
			"reset_password_url": func() string {
				resetPasswordURL := utils.GetAbsURL(context.Request)
				resetPasswordURL.Path = path.Join(context.Auth.AuthURL("password/edit"), context.SessionStorer.SignedToken(claims))
				return resetPasswordURL.String()
			},
		}),
	)
}

func NewPasswordToken(context *auth.Context, email string) string {
	var (
		authInfo    auth_identity.Basic
		provider, _ = context.Provider.(*Provider)
	)

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(email)
	claims := authInfo.ToClaims()
	token := context.SessionStorer.SignedToken(claims)
	return token
}

// DefaultRecoverPasswordHandler default reset password handler
var DefaultRecoverPasswordHandler = func(context *auth.Context) error {
	context.Request.ParseForm()

	var (
		authInfo    auth_identity.Basic
		email       = context.Request.Form.Get("email")
		provider, _ = context.Provider.(*Provider)
	)

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(email)

	currentUser, err := context.Auth.UserStorer.Get(authInfo.ToClaims(), context)

	if err != nil {
		return err
	}

	err = provider.ResetPasswordMailer(email, context, authInfo.ToClaims(), currentUser)

	if err == nil {
		context.SessionStorer.Flash(context.SessionManager(), session.Message{Message: SendChangePasswordMailFlashMessage, Type: "success"})
		context.Auth.Redirector.Redirect(context.Writer, context.Request, "send_recover_password_mail")
	}
	return err
}

// DefaultResetPasswordHandler default reset password handler
var DefaultResetPasswordHandler = func(context *auth.Context) error {
	context.Request.ParseForm()

	var (
		authInfo    auth_identity.Basic
		token       = context.Request.Form.Get("reset_password_token")
		provider, _ = context.Provider.(*Provider)
		db          = context.DB
	)

	claims, err := context.SessionStorer.ValidateClaims(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			authInfo.Provider = provider.GetName()
			authInfo.UID = claims.Id
			authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()

			if db.Where(authInfo).First(authIdentity).RecordNotFound() {
				return auth.ErrInvalidAccount
			}

			if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(strings.TrimSpace(context.Request.Form.Get("new_password"))); err == nil {
				// Confirm account after reset password, as user already click a link from email
				if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now
				}
				err = db.Model(authIdentity).Update(authInfo).Error
			}
		}
	}

	if err == nil {
		context.SessionStorer.Flash(context.SessionManager(), session.Message{Message: ChangedPasswordFlashMessage, Type: "success"})
		context.Auth.Redirector.Redirect(context.Writer, context.Request, "reset_password")
	}
	return err
}

// DefaultResetPasswordHandler default reset password handler
var DefaultUpdatePasswordHandler = func(context *auth.Context) error {
	context.Request.ParseForm()

	var (
		authInfo    auth_identity.Basic
		token       = context.Request.Form.Get("reset_password_token")
		provider, _ = context.Provider.(*Provider)
		db          = context.DB
	)

	claims, err := context.SessionStorer.ValidateClaims(token)

	if err == nil {
		if err = claims.Valid(); err == nil {
			authInfo.Provider = provider.GetName()
			authInfo.UID = claims.Id
			authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()

			if db.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
				return auth.ErrInvalidAccount
			}

			currentPassword := context.Request.Form.Get("current_password")
			if currentPassword == "" {
				return errors.New(context.Ts(context.Auth.I18n("form.current_password_placeholder")))
			}
			if err := provider.Encryptor.Compare(authInfo.EncryptedPassword, currentPassword); err != nil {
				if err == bcrypt.ErrMismatchedHashAndPassword {
					return fmt.Errorf(context.Ts(context.Auth.I18n("passwords.current_password_not_match")))
				} else {
					return err
				}
			}

			newPassword := context.Request.Form.Get("new_password")
			passwordConfirm := context.Request.Form.Get("password_confirm")
			if newPassword != passwordConfirm {
				return errors.New(context.Ts(context.Auth.I18n("passwords.passwords_not_match")))
			}

			result, err := zxcvbn_fb.Zxcvbn(newPassword)
			if err != nil {
				return fmt.Errorf("Validate Password Failed: %v", err)
			}

			if result.Score <= 2 {
				msg := result.Feedback.Warning
				if msg != "" && len(result.Feedback.Suggestions) > 0 {
					msg += ": " + strings.Join(result.Feedback.Suggestions, ". ")
				}
				return errors.New(msg)
			}

			if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(newPassword); err == nil {
				// Confirm account after reset password, as user already click a link from email
				if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
					now := time.Now()
					authInfo.ConfirmedAt = &now
				}
				err = db.Model(authIdentity).Update(authInfo).Error
			}
		}
	}

	if err == nil {
		context.SessionStorer.Flash(context.SessionManager(), session.Message{Message: ChangedPasswordFlashMessage, Type: "success"})
	}
	return err
}
