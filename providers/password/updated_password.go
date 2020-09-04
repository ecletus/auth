package password

import (
	"github.com/moisespsena-go/aorm"
	"net/mail"

	"github.com/ecletus/auth"
	"github.com/ecletus/mailer"
	"github.com/moisespsena/template/html/template"
)

// DefaultUpdatePasswordMailer default update password mailer
var DefaultUpdatedPasswordNotifier = func(TO []mail.Address, context *auth.Context, user auth.User, passwd string) error {
	Mailer := mailer.FromSite(context.Site)
	if Mailer == nil {
		log.Warningf("No mailer for %q. Password for user %q#%s is %q", context.Site.Name(), user.Schema().Name, aorm.IdOf(user), passwd)
		return nil
	}
	if you := user.Schema().MailAddress(); you != nil {
		subject := context.Ts(ChangedPasswordFlashMessage)
		if err := Mailer.Send(
			&mailer.Email{
				Context: context,
				Lang:    append(user.Schema().Lang, context.GetI18nContext().Locales()...),
				TO:      []mail.Address{*you},
				Subject: subject,
			}, mailer.Template{
				Name:    "auth/password/you_password_updated",
				Data:    context,
				Context: context.Context,
			}.Funcs(template.FuncMap{
				"you": func() *mail.Address {
					return you
				},
				"user": func() interface{} {
					return user
				},
				"login_url": func() string {
					return context.AuthURL("login")
				},
				"user_info": func() *auth.Schema {
					return user.Schema()
				},
				"has_password": func() bool {
					return passwd != ""
				},
				"password": func() string {
					return passwd
				},
			}),
		); err != nil {
			return err
		}
	}
	return Mailer.Send(
		&mailer.Email{
			Context: context,
			Lang:    context.GetI18nContext().Locales(),
			TO:      TO,
			Subject: context.Ts(ResetPasswordMailSubject),
		}, mailer.Template{
			Name:    "auth/password/updated_password",
			Data:    context,
			Context: context.Context,
		}.Funcs(template.FuncMap{
			"user": func() interface{} {
				return user
			},
			"login_url": func() string {
				return context.AuthURL("login")
			},
			"user_info": func() *auth.Schema {
				return user.Schema()
			},
			"has_password": func() bool {
				return passwd != ""
			},
			"password": func() string {
				return passwd
			},
		}),
	)
}
