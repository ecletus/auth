package password

import (
	"net/mail"
	"path"
	"strings"

	"github.com/aghape/auth"
	"github.com/aghape/auth/auth_identity"
	"github.com/aghape/auth/claims"
	"github.com/aghape/core/utils"
	"github.com/aghape/mailer"
	"github.com/aghape/session"
	"github.com/moisespsena/template/html/template"
)

var (
	// ResetPasswordMailSubject reset password mail's subject
	ResetPasswordMailSubject = I18N_GROUP + ".reset_your_password"

	// SendChangePasswordMailFlashMessage send change password mail flash message
	SendChangePasswordMailFlashMessage = I18N_GROUP + ".change_password_mail_body"

	// ChangedPasswordFlashMessage changed password success flash message
	ChangedPasswordFlashMessage = I18N_GROUP + ".your_password_changed"
)

// DefaultResetPasswordMailer default reset password mailer
var DefaultResetPasswordMailer = func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error {
	claims.Subject = "reset_password"

	return context.Auth.Mailer.Send(
		mailer.Email{
			TO:      []mail.Address{{Address: email}},
			Subject: context.Ts(ResetPasswordMailSubject),
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
	cl := authInfo.ToClaims()
	token := context.SessionStorer.SignedToken(cl)
	return token
}

// DefaultRecoverPasswordHandler default reset password handler
var DefaultRecoverPasswordHandler = func(context *auth.Context) error {
	_ = context.Request.ParseForm()

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
		_ = context.SessionStorer.Flash(context.SessionManager(), session.Message{Message: context.T(SendChangePasswordMailFlashMessage), Type: "success"})
		context.Auth.Redirector.Redirect(context.Writer, context.Request, "send_recover_password_mail")
	}
	return err
}

// DefaultResetPasswordHandler default reset password handler
var DefaultResetPasswordHandler = func(context *auth.Context) error {
	_ = context.Request.ParseForm()
	pu := &PasswordUpdater{
		Confirmed:               false,
		CurrentPasswordDisabled: true,
	}
	return pu.Context(context)
}

// DefaultResetPasswordHandler default reset password handler
var DefaultUpdatePasswordHandler = func(context *auth.Context) error {
	_ = context.Request.ParseForm()
	pu := &PasswordUpdater{
		StrengthDisabled: true,
	}
	return pu.Context(context)
}
