package auth

import (
	"strings"

	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core"
	qorconfig "github.com/ecletus/core/config"
	"github.com/ecletus/mailer"
	"github.com/ecletus/mailer/logger"
	"github.com/ecletus/redirect_back"
	"github.com/ecletus/render"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/moisespsena/template/funcs"
)

// Auth auth struct
type Auth struct {
	*Config
	// Embed SessionStorer to match Authority's AuthInterface
	SessionStorerInterface
	providers map[string]Provider
	Funcs     *funcs.FuncValues
}

// Config auth config
type Config struct {
	*qorconfig.Config
	// AuthIdentityModel a model used to save auth info, like email/password, OAuth token, linked user's ID, https://github.com/ecletus/auth/blob/master/auth_identity/auth_identity.go is the default implemention
	AuthIdentityModel interface{}
	// UserModel should be point of user struct's instance, it could be nil, then Auth will assume there is no user linked to auth info, and will return current auth info when get current user
	UserModel interface{}
	// Mount Auth into router with URLPrefix's value as prefix, default value is `/auth`.
	URLPrefix string

	// Auth is using [Render](https://github.com/ecletus/render) to render pages, you could configure it with your project's Render if you have advanced usage like [BindataFS](https://github.com/ecletus/bindatafs)
	Render *render.Render
	// Auth is using [Mailer](https://github.com/ecletus/mailer) to send email, by default, it will print email into console, you need to configure it to send real one
	Mailer *mailer.Mailer
	// UserStorer is an interface that defined how to get/save user, Auth provides a default one based on AuthIdentityModel, UserModel's definition
	UserStorer UserStorerInterface
	// SessionStorer is an interface that defined how to encode/validate/save/destroy session data and flash messages between requests, Auth provides a default method do the job, to use the default value, don't forgot to mount SessionManager's middleware into your router to save session data correctly. refer [session](https://github.com/ecletus/session) for more details
	SessionStorer SessionStorerInterface
	// Redirector redirect user to a new page after registered, logged, confirmed...
	Redirector RedirectorInterface

	// LoginHandler defined behaviour when request `{Auth Prefix}/login`, default behaviour defined in http://godoc.org/github.com/ecletus/auth#pkg-variables
	LoginHandler func(*Context, func(*Context) (*claims.Claims, error))
	// RegisterHandler defined behaviour when request `{Auth Prefix}/register`, default behaviour defined in http://godoc.org/github.com/ecletus/auth#pkg-variables
	RegisterHandler func(*Context, func(*Context) (*claims.Claims, error))
	// LogoutHandler defined behaviour when request `{Auth Prefix}/logout`, default behaviour defined in http://godoc.org/github.com/ecletus/auth#pkg-variables
	LogoutHandler func(*Context)
	// ProfileHandler defined behaviour when request `{Auth Prefix}/profile`, default behaviour defined in http://godoc.org/github.com/ecletus/auth#pkg-variables
	ProfileHandler func(*Context)

	// RegistrableFunc Check if Allow register new users
	RegistrableFunc func(auth *Auth, ctx *core.Context) bool

	LoginPageRedirectTo string

	ContextFactory *core.ContextFactory
}

// New initialize Auth
func New(config *Config) *Auth {
	if config == nil {
		config = &Config{}
	}

	if config.URLPrefix == "" {
		config.URLPrefix = "/auth"
	} else {
		config.URLPrefix = "/" + strings.Trim(config.URLPrefix, "/")
	}

	if config.AuthIdentityModel == nil {
		config.AuthIdentityModel = &auth_identity.AuthIdentity{}
	}

	if config.Render == nil {
		config.Render = render.New(nil)
	}

	if config.Mailer == nil {
		config.Mailer = mailer.New(&mailer.Config{
			Sender: logger.New(&logger.Config{}),
		})
	}

	if config.UserStorer == nil {
		config.UserStorer = &UserStorer{}
	}

	if config.SessionStorer == nil {
		config.SessionStorer = &SessionStorer{
			SessionName:   "_auth_session",
			SigningMethod: jwt.SigningMethodHS256,
		}
	}

	if config.Redirector == nil {
		config.Redirector = &Redirector{redirect_back.New(&redirect_back.Config{
			IgnoredPrefixes: []string{config.URLPrefix + "/"},
		})}
	}

	if config.LoginHandler == nil {
		config.LoginHandler = DefaultLoginHandler
	}

	if config.RegisterHandler == nil {
		config.RegisterHandler = DefaultRegisterHandler
	}

	if config.LogoutHandler == nil {
		config.LogoutHandler = DefaultLogoutHandler
	}

	if config.ProfileHandler == nil {
		config.ProfileHandler = DefaultProfileHandler
	}

	if config.LoginPageRedirectTo == "" {
		config.LoginPageRedirectTo = config.URLPrefix + "/profile"
	}

	auth := &Auth{Config: config}

	auth.SessionStorerInterface = config.SessionStorer
	auth.providers = make(map[string]Provider)
	var err error
	auth.Funcs, err = funcs.CreateValuesFunc(map[string]interface{}{
		"prefix": func() string {
			return auth.URLPrefix
		},
		"qor_auth_page": func(context *core.Context) string {
			v := context.Data().Get(AUTH_URL_KEY + ".page")
			if v != nil {
				return v.(string)
			}
			return ""
		},
		"qor_auth_url": func(context *core.Context, args ...string) interface{} {
			authURL := AuthURLFromContext(context)
			if len(args) == 0 {
				return authURL
			}
			switch args[0] {
			case "login":
				return authURL.LoginPage()
			case "logout":
				return authURL.LogoutPage()
			case "redirect_login":
				return authURL.LoginPage(true)
			case "redirect_logout":
				return authURL.LogoutPage(true)
			}
			return ""
		},
		"qor_auth_prefix": func(context *core.Context) string {
			return auth.URLPrefix
		},
		"qor_auth_is_registrable": auth.Registrable,
	})
	if err != nil {
		panic(err)
	}
	config.Render.Funcs().AppendValues(auth.Funcs)
	return auth
}

func (auth *Auth) Registrable(context *core.Context) bool {
	if auth.RegistrableFunc != nil {
		return auth.RegistrableFunc(auth, context)
	}
	return true
}

func (auth *Auth) I18n(key ...string) string {
	return I18n(key...)
}

func I18n(key ...string) string {
	if len(key) > 0 && key[0] != "" {
		return I18N_GROUP + "." + key[0]
	}
	return I18N_GROUP
}
