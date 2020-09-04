package auth

import (
	"context"
	"net/http"

	"github.com/ecletus/redirect_back"
	"github.com/moisespsena-go/xroute"

	"github.com/ecletus/core"
)

type AuthURL struct {
	context *core.Context
	Prefix  string
}

func (a *AuthURL) Redirect(url string) {
	redirect_back.Set(a.context)
	http.Redirect(a.context.Writer, a.context.Request, url, http.StatusSeeOther)
}

func (a *AuthURL) LoginPage(redirect ...bool) (url string) {
	url = a.Prefix + "/login"
	if len(redirect) > 0 && redirect[0] {
		a.Redirect(url)
	}
	return
}

func (a *AuthURL) LoginReturn() {
	urls := a.Prefix + "/login"
	a.Redirect(urls)
	return
}

func (a *AuthURL) LogoutPage(redirect ...bool) (url string) {
	url = a.Prefix + "/logout"
	if len(redirect) > 0 && redirect[0] {
		a.Redirect(url)
	}
	return
}

var AUTH_URL_KEY = PREFIX + ".auth.url"

func (auth *Auth) URL(r *http.Request) *AuthURL {
	context := core.ContextFromRequest(r)
	url := context.Value(AUTH_URL_KEY).(*AuthURL)
	return url
}

func (auth *Auth) Middleware() *xroute.Middleware {
	return &xroute.Middleware{
		Name: PREFIX,
		Handler: func(chain *xroute.ChainHandler) {
			context := core.ContextFromRequest(chain.Request())
			authUrl := context.Top().Path(auth.URLPrefix)
			context.
				SetValue(PREFIX, auth).
				SetValue(AUTH_URL_KEY, &AuthURL{context, authUrl})
			chain.Pass()
		},
	}
}

func AuthURLFromContext(context context.Context) *AuthURL {
	return context.Value(AUTH_URL_KEY).(*AuthURL)
}
