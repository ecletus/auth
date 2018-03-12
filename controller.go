package auth

import (
	"net/http"
	"path"
	"strings"

	"github.com/qor/auth/claims"
	"github.com/moisespsena/template/html/template"
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
		reqPath = strings.TrimPrefix(req.URL.Path, serveMux.URLPrefix + "/")
		paths   = strings.Split(reqPath, "/")
	)

	req, context := NewContextFromRequestPair(w, req, serveMux.Auth, claims)

	render := serveMux.Auth.Render.Template().Funcs(template.FuncMap{
		"prefix": func() string {
			return serveMux.Auth.URLPrefix
		},
	})

	if len(paths) >= 2 {
		// render assets
		if paths[0] == "assets" {
			DefaultAssetHandler(context)
			return
		}

		providerName := context.JoinPath(paths[0])
		provider := serveMux.Auth.GetProvider(providerName)

		if provider == nil {
			provider = serveMux.Auth.GetProvider(paths[0])
		}

		// eg: /phone/login
		if provider != nil {
			context.Provider = provider

			// serve mux
			switch paths[1] {
			case "login":
				if context.GetCurrentUser(req) != nil {
					redirectTo := context.GenURL(serveMux.LoginPageRedirectTo)
					http.Redirect(w, req, redirectTo, http.StatusSeeOther)
				} else {
					provider.Login(context)
				}
			case "logout":
				provider.Logout(context)
			case "register":
				if serveMux.Registrable(context) {
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
			// render login page
			render.Execute("auth/login", context, context.Context)
		case "profile":
			if context.GetCurrentUser(req) != nil {
				serveMux.Auth.ProfileHandler(context)
			} else {
				redirectTo := context.AuthURL("login") + "?return_to="
				serveMux.Redirector.Redirect(w, req, redirectTo)
			}
		case "register":
			// render register page
			if serveMux.Registrable(context) {
				render.Execute("auth/register", context, context.Context)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
		case "logout":
			// destroy login context
			serveMux.Auth.LogoutHandler(context)
		default:
			http.NotFound(w, req)
		}
		return
	}

	http.NotFound(w, req)
}

// AuthURL generate URL for auth
func (auth *Auth) AuthURL(pth string) string {
	return path.Join(auth.URLPrefix, pth)
}
