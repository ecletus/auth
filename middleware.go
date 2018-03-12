package auth

import (
	"net/http"
	"github.com/qor/qor"
	"github.com/qor/middlewares"
)

type AuthURL struct {
	context *qor.Context
	Prefix  string
}

func (a *AuthURL) Redirect(url string) {
	http.Redirect(a.context.Writer, a.context.Request, url, http.StatusSeeOther)
}

func (a *AuthURL) LoginPage(redirect ... bool) (url string) {
	url = a.Prefix + "/login"
	if len(redirect) > 0 && redirect[0] {
		a.Redirect(url)
	}
	return
}

func (a *AuthURL) LogoutPage(redirect ... bool) (url string) {
	url = a.Prefix + "/logout"
	if len(redirect) > 0 && redirect[0] {
		a.Redirect(url)
	}
	return
}

func (auth *Auth) URL(r *http.Request) *AuthURL {
	context := qor.ContextFromRequest(r)
	url := context.Data().Get("qor_auth:url").(*AuthURL)
	return url
}

func (auth *Auth) Handler() func(http.Handler)http.Handler {
	return func(handler http.Handler)http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r, context := qor.GetOrNewContextFromRequestPair(w, r)
			data := context.Data().Inside()
			defer context.Data().Outside()
			authUrl := context.GenGlobalURL(auth.URLPrefix)
			data.Set("qor_auth:url", &AuthURL{context, authUrl})
			handler.ServeHTTP(w, r)
		})
	}
}

func (auth *Auth) Middleware() middlewares.Middleware {
	return middlewares.Middleware{
		Name:    "qor:auth",
		Handler: func(handler http.Handler) http.Handler {
			return auth.Handler()(handler)
		},
	}
}
