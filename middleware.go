package auth

import (
	"net/http"
	"github.com/aghape/aghape"
	"github.com/moisespsena/go-route"
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

var AUTH_URL_KEY = PREFIX + ".auth.url"

func (auth *Auth) URL(r *http.Request) *AuthURL {
	context := qor.ContextFromRequest(r)
	url := context.Data().Get(AUTH_URL_KEY).(*AuthURL)
	return url
}

func (auth *Auth) Middleware() *route.Middleware {
	return &route.Middleware{
		Name:PREFIX,
		Handler: func(chain *route.ChainHandler) {
			context := qor.ContexFromChain(chain)
			authUrl := context.GenGlobalURL(auth.URLPrefix)
			context.Data().Set(PREFIX, auth, AUTH_URL_KEY, &AuthURL{context, authUrl})
			chain.Pass()
		},
	}
}

func AuthURLFromContext(context *qor.Context) *AuthURL {
	return context.Data().Get(AUTH_URL_KEY).(*AuthURL)
}