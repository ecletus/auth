package password

import (
	"net/mail"
	"strings"
	"time"

	"github.com/moisespsena-go/tzdb"

	"github.com/ecletus/auth/auth_identity/helpers"

	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/mailer"
	"github.com/ecletus/session"
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
var DefaultResetPasswordMailer = func(ctx *auth.Context, claims *claims.Claims, currentUser auth.User, email ...string) error {
	claims.Subject = "reset_password"
	expireAt := time.Unix(claims.ExpiresAt, 0)
	if location := currentUser.Schema().Location; location != "" {
		expireAt = expireAt.In(tzdb.LocationCity(location).Location())
	}
	if len(email) == 0 || email[0] == "" {
		email = []string{currentUser.Schema().Email}
	}
	Mailer := mailer.FromSite(ctx.Site)
	return Mailer.Send(
		&mailer.Email{
			Context: ctx,
			Lang:    ctx.GetI18nContext().Locales(),
			TO:      []mail.Address{{Address: email[0]}},
			Subject: ctx.Ts(ResetPasswordMailSubject),
		}, mailer.Template{
			Name:    "auth/password/reset_password",
			Data:    ctx,
			Context: ctx.Context,
		}.Funcs(template.FuncMap{
			"current_user": func() interface{} {
				return currentUser
			},
			"expire_at": func() time.Time {
				return expireAt
			},
			"reset_password_url": func() string {
				token, err := ctx.SessionStorer.SignedToken(claims)
				if err != nil {
					return "{TOKEN ERROR=" + err.Error() + "}"
				}
				url := ctx.AuthURL("password/edit", token)
				return url
			},
		}),
	)
}

func NewPasswordToken(ctx *auth.Context, email string) (string, error) {
	var (
		authInfo    auth_identity.Basic
		provider, _ = ctx.Provider.(*Provider)
	)

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(email)
	cl := authInfo.ToClaims()
	return ctx.SessionStorer.SignedToken(cl)
}

// DefaultRecoverPasswordHandler default reset password handler
var DefaultRecoverPasswordHandler = func(ctx *auth.Context) (err error) {
	_ = ctx.Request.ParseForm()

	var (
		authInfo    *auth_identity.Basic
		identity    auth_identity.AuthIdentityInterface
		identifier  = ctx.Request.Form.Get("email")
		provider, _ = ctx.Provider.(*Provider)
		uid         string
	)

	if uid, err = ctx.Auth.FindUID(ctx, identifier); err != nil {
		return
	}

	if identity, err = helpers.GetIdentity(ctx.Auth.AuthIdentityModel, provider.GetName(), ctx.DB(), uid); err != nil {
		return
	}

	authInfo = identity.GetAuthBasic()
	authInfo.Provider = provider.GetName()

	currentUser, err := ctx.Auth.UserStorer.Get(authInfo.ToClaims(), ctx)

	if err != nil {
		return err
	}

	Claims := authInfo.ToClaims()
	Claims.ExpiresAt = time.Now().Add(time.Minute * 30).Unix()
	if err = provider.ResetPasswordMailer(ctx, Claims, currentUser); err == nil {
		_ = ctx.SessionStorer.Flash(ctx.SessionManager(), session.Message{Message: ctx.T(SendChangePasswordMailFlashMessage), Type: "success"})
		ctx.Auth.Redirector.Redirect(ctx.Writer, ctx.Request, "send_recover_password_mail")
	}
	return err
}

// DefaultResetPasswordHandler default reset password handler
var DefaultResetPasswordHandler = func(ctx *auth.Context, updatedMailer UpdatedPasswordNotifier) (Claims *claims.Claims, err error) {
	_ = ctx.Request.ParseForm()
	pu := &PasswordUpdater{
		CurrentPasswordDisabled: true,
		NotifyMailer:            updatedMailer,
	}
	return pu.Context(ctx)
}
