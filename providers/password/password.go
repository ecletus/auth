package password

import (
	"net/http"
	"net/mail"
	"net/url"
	"strings"

	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/auth/providers/password/encryptor"
	"github.com/ecletus/auth/providers/password/encryptor/bcrypt_encryptor"
	"github.com/ecletus/session"
	"github.com/moisespsena-go/maps"
	"github.com/moisespsena/template/html/template"
)

const (
	Name          = "password"
	FieldLogin    = "login"
	FieldPassword = "password"
)

type UpdatedPasswordNotifier interface {
	Notify(TO []mail.Address, context *auth.Context, user auth.User, passwd string) error
}

type UpdatedPasswordNotifierFunc func(TO []mail.Address, context *auth.Context, user auth.User, passwd string) error

func (this UpdatedPasswordNotifierFunc) Notify(TO []mail.Address, context *auth.Context, user auth.User, passwd string) error {
	return this(TO, context, user, passwd)
}

// Config password config
type Config struct {
	Confirmable    bool
	ConfirmMailer  func(email string, context *auth.Context, claims *claims.Claims, currentUser interface{}) error
	ConfirmHandler func(*auth.Context) error

	ResetPasswordMailer    func(context *auth.Context, claims *claims.Claims, currentUser auth.User, email...string) error
	ResetPasswordHandler   func(*auth.Context, UpdatedPasswordNotifier) (Claims *claims.Claims, err error)
	RecoverPasswordHandler func(*auth.Context) error

	Encryptor        encryptor.Interface
	AuthorizeHandler func(*auth.LoginContext) (*claims.Claims, error)
	RegisterHandler  func(*auth.Context) (*claims.Claims, error)

	UpdatedPasswordNotifier UpdatedPasswordNotifier
}

// New initialize password provider
func New(config *Config) *Provider {
	if config == nil {
		config = &Config{}
	}

	if config.Encryptor == nil {
		config.Encryptor = bcrypt_encryptor.New(&bcrypt_encryptor.Config{})
	}

	provider := &Provider{Config: config}

	if config.ConfirmMailer == nil {
		config.ConfirmMailer = DefaultConfirmationMailer
	}

	if config.ConfirmHandler == nil {
		config.ConfirmHandler = DefaultConfirmHandler
	}

	if config.ResetPasswordMailer == nil {
		config.ResetPasswordMailer = DefaultResetPasswordMailer
	}

	if config.ResetPasswordHandler == nil {
		config.ResetPasswordHandler = DefaultResetPasswordHandler
	}

	if config.RecoverPasswordHandler == nil {
		config.RecoverPasswordHandler = DefaultRecoverPasswordHandler
	}

	if config.AuthorizeHandler == nil {
		config.AuthorizeHandler = DefaultAuthorizeHandler
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = DefaultRegisterHandler
	}

	if config.UpdatedPasswordNotifier == nil {
		config.UpdatedPasswordNotifier = UpdatedPasswordNotifierFunc(DefaultUpdatedPasswordNotifier)
	}

	return provider
}

// Provider provide login with password method
type Provider struct {
	*Config
}

// GetName return provider name
func (Provider) GetName() string {
	return Name
}

// I18n returh i18n key prefix
func (p Provider) I18n(key ...string) string {
	if len(key) > 0 && key[0] != "" {
		return I18N_GROUP + "." + key[0]
	}
	return I18N_GROUP
}

// ConfigAuth config auth
func (provider Provider) ConfigAuth(auth *auth.Auth) {
}

func (provider Provider) ParseValues(values url.Values) (data maps.Map, err error) {
	login, password := values.Get(FieldLogin), values.Get(FieldPassword)
	if login == "" {
		return nil, auth.ErrInvalidAccount
	}
	if password == "" {
		return nil, auth.ErrInvalidPassword
	}
	return *data.
			Set(FieldLogin, login).
			Set(FieldPassword, password),
		nil
}

func (provider Provider) ParseRequestForm(req *http.Request) (data maps.Map, err error) {
	if err = req.ParseForm(); err != nil {
		return
	}
	return provider.ParseValues(req.Form)
}

func (provider Provider) SetLoginPassword(context *auth.LoginContext, login, password string) *auth.LoginContext {
	context.LoginData.Set(FieldLogin, login).Set(FieldPassword, password)
	return context
}

func (provider Provider) PrepareLoginContext(context *auth.LoginContext) (err error) {
	if !context.LoginData.Has(FieldLogin, FieldPassword) {
		var data maps.Map
		if data, err = provider.ParseRequestForm(context.Request); err != nil {
			return
		}
		context.LoginData.Update(data)
	}
	return
}

// Login implemented login with password provider
func (provider Provider) Login(context *auth.LoginContext) (*claims.Claims, error) {
	return context.Auth.LoginHandler(context, provider.AuthorizeHandler)
}

// Register implemented register with password provider
func (provider Provider) Register(context *auth.Context) {
	context.Auth.RegisterHandler(context, provider.RegisterHandler)
}

// Logout implemented logout with password provider
func (provider Provider) Logout(context *auth.Context) {
	context.Auth.LogoutHandler(context)
}

// Callback implement Callback with password provider
func (provider Provider) Callback(context *auth.Context) {
}

// ServeHTTP implement ServeHTTP with password provider
func (provider Provider) ServeHTTP(context *auth.Context) {
	var (
		req     = context.Request
		reqPath = strings.TrimPrefix(req.URL.Path, context.Auth.URLPrefix+"/")
		paths   = strings.Split(reqPath, "/")
	)

	if len(paths) >= 2 {
		switch paths[1] {
		case "confirmation":
			var err error

			if len(paths) >= 3 {
				switch paths[2] {
				case "new":
					// render new confirmation page
					context.Auth.Config.Render.Execute("auth/password/confirmation/new", context, context.Context)
				case "send":
					var (
						currentUser interface{}
						authInfo    auth_identity.Basic
						db          = context.DB()
						err         error
					)

					authInfo.Provider = provider.GetName()
					authInfo.UID, err = context.Auth.FindUID(context, req.Form.Get("email"))

					if db.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
						err = auth.ErrInvalidAccount
					} else if err == nil {
						if currentUser, err = context.Auth.UserStorer.Get(authInfo.ToClaims(), context); err == nil {
							err = provider.Config.ConfirmMailer(authInfo.UID, context, authInfo.ToClaims(), currentUser)
						}
					}

					if err == nil {
						context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), err))
						context.Auth.Redirector.Redirect(context.Writer, context.Request, "send_confirmation")
					}
				}
			}

			if err != nil {
				context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), err))
			}
			// render new confirmation page
			context.Auth.Config.Render.Execute("auth/confirmation/new", context, context.Context)
		case "confirm":
			// confirm user
			err := provider.ConfirmHandler(context)
			if err != nil {
				context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), err))
				context.Auth.Redirector.Redirect(context.Writer, context.Request, "confirm_failed")
				return
			}
		case "new":
			// render change password page
			context.Auth.Config.Render.Execute("auth/password/new", context, context.Context)
		case "recover":
			// send recover password mail
			err := provider.RecoverPasswordHandler(context)
			if err != nil {
				context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), err))
				http.Redirect(context.Writer, context.Request, context.AuthPath("password/new"), http.StatusSeeOther)
				return
			}
		case "edit":
			// render edit password page
			if len(paths) == 3 {
				if _, err := context.SessionStorer.ValidateClaims(paths[2]); err != nil {
					context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), err))
					http.Redirect(context.Writer, context.Request, context.AuthPath("password/new"), http.StatusSeeOther)
					return
				}
				context.Auth.Config.Render.Template().SetFuncs(template.FuncMap{
					"reset_password_token": func() string { return paths[2] },
				}).Execute("auth/password/edit", context, context.Context)
				return
			}
			context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), ErrInvalidResetPasswordToken))
			http.Redirect(context.Writer, context.Request, context.AuthPath("password/new"), http.StatusSeeOther)
		case "update":
			if req.Method == "POST" {
				// update password
				_, err := provider.ResetPasswordHandler(context, provider.UpdatedPasswordNotifier)
				if err == nil {
					redirectTo := context.Path(context.AuthPath("profile"))
					http.Redirect(context.Writer, context.Request, redirectTo, http.StatusSeeOther)
					return
				}
				//if err = provider.UpdatedPasswordNotifier()
				context.SessionStorer.Flash(context.SessionManager(), session.TranslatedMessageE(context.GetI18nContext(), err))
				redirectTo := context.Path(context.AuthPath("password/edit", context.Request.FormValue("reset_password_token")))
				http.Redirect(context.Writer, context.Request, redirectTo, http.StatusSeeOther)
				return
			} else {
				user, err := context.Auth.GetCurrentUser(req)
				if err == nil {
					token, err := NewPasswordToken(context, user.GetEmail())
					if err != nil {
						http.Error(context.Writer, err.Error(), http.StatusInternalServerError)
						return
					}
					context.Auth.Config.Render.Template().SetFuncs(template.FuncMap{
						"reset_password_token": func() string { return token },
					}).Execute("auth/password/update", context, context.Context)
				} else {
					http.Error(context.Writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}

	return
}

func GetProvider(Auth *auth.Auth) *Provider {
	p := Auth.GetProvider(Name)
	if p != nil {
		return p.(*Provider)
	}
	return nil
}
