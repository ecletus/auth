package auth

import (
	"net/http"
	"path"
	"strings"

	"github.com/ecletus/auth/claims"
)

// NewServeMux generate http.Handler for auth
func (auth *Auth) NewServeMux() http.Handler {
	return &serveMux{Auth: auth}
}

type serveMux struct {
	*Auth
}

// ServeHTTP dispatches the handler registered in the matched route
func (serveMux *serveMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var (
		claims  *claims.Claims
		reqPath = strings.TrimPrefix(req.URL.Path, serveMux.URLPrefix+"/")
		paths   = strings.Split(reqPath, "/")
		render  = serveMux.Auth.Render.Template()
	)

	req, context := serveMux.NewContextFromRequestPair(w, req, claims)

	if len(paths) >= 2 {
		// render assets
		if paths[0] == "assets" {
			DefaultAssetHandler(context)
			return
		}

		var (
			providerName = context.JoinPath(paths[0])
			Auth         = serveMux.Auth
			provider     = Auth.GetProvider(providerName)
		)

		if provider == nil {
			provider = Auth.GetProvider(paths[0])
		}

		// eg: /phone/login
		if provider != nil {
			context.Provider = provider

			// serve mux
			switch paths[1] {
			case "login":
				w := context.Writer

				if user, err := context.GetCurrentUser(req); user != nil {
					redirectTo := context.Path(serveMux.LoginPageRedirectTo)
					http.Redirect(w, req, redirectTo, http.StatusSeeOther)
				} else {
					if err == nil || err == ErrNoSession {
						_, err = Auth.Login(&LoginContext{Context: context})
						// TODO: log errors per site
					}
					if w.WroteHeader() {
						return
					}
					if err != nil {
						context.AddError(err)
						// render login page
						context.SetValue(AUTH_URL_KEY+".page", "login")
						render.Execute("auth/login", context, context.Context)
						return
					}
				}

				http.NotFound(w, req)
			case "logout":
				provider.Logout(context)
			case "register":
				if serveMux.Registrable(context.Context) {
					provider.Register(context)
				} else {
					w.WriteHeader(http.StatusForbidden)
				}
			case "callback":
				provider.Callback(context)
			default:
				provider.ServeHTTP(context)
			}
			return
		}
	} else if len(paths) == 1 {
		// eg: /login, /logout
		switch paths[0] {
		case "login":
			if user, err := context.GetCurrentUser(req); user != nil {
				serveMux.Redirector.Redirect(w, req, serveMux.LoginPageRedirectTo)
			} else {
				if err != ErrNoSession {
					context.AddError(err)
				}
				// render login page
				context.SetValue(AUTH_URL_KEY+".page", "login")
				if err = render.Execute("auth/login", context, context.Context); err != nil {
					panic(err)
				}
			}
		case "profile":
			if user, err := context.GetCurrentUser(req); user != nil {
				context.SetValue(AUTH_URL_KEY+".page", "profile")
				serveMux.Auth.ProfileHandler(context)
			} else {
				if err != ErrNoSession {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				redirectTo := context.AuthPath("login") + "?return_to="
				serveMux.Redirector.Redirect(w, req, redirectTo)
			}
		case "register":
			// render register page
			if serveMux.Registrable(context.Context) {
				context.SetValue(AUTH_URL_KEY+".page", "register")
				render.Execute("auth/register", context, context.Context)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
		case "logout":
			context.SetValue(AUTH_URL_KEY+".page", "logout")
			// destroy login context
			serveMux.Auth.LogoutHandler(context)
		default:
			http.NotFound(w, req)
		}
		return
	}

	http.NotFound(w, req)
}

// AuthPath generate URL for auth
func (auth *Auth) AuthPath(pth ...string) string {
	return path.Join(append([]string{auth.URLPrefix}, pth...)...)
}
