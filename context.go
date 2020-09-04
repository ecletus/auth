package auth

import (
	"net/http"

	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core"
	"github.com/ecletus/session"
	"github.com/moisespsena-go/maps"
)

type LoginContext struct {
	*Context
	LoginCallbacks

	UID         string
	LoginData   maps.Map
	Silent      bool
	SilentError bool
}

// Context context
type Context struct {
	*core.Context
	*Auth
	Claims   *claims.Claims
	Provider Provider
}

func (context *Context) GetContext() *core.Context {
	return context.Context
}

func (this *LoginContext) Before(f ...func(ctx *LoginContext) error) *LoginContext {
	this.LoginCallbacks.Before(f...)
	return this
}

func (this *LoginContext) Info(f ...func(ctx *LoginContext, info *auth_identity.Basic) error) *LoginContext {
	this.LoginCallbacks.Info(f...)
	return this
}

func (this *LoginContext) Logged(f ...func(ctx *LoginContext, claims *claims.Claims) error) *LoginContext {
	this.LoginCallbacks.Logged(f...)
	return this
}

func (this *LoginContext) Failure(f ...func(ctx *LoginContext, err error)) *LoginContext {
	this.LoginCallbacks.Failure(f...)
	return this
}

func (this *LoginContext) Login() (Claims *claims.Claims, err error) {
	return this.Provider.Login(this)
}

// Flashes get flash messages
func (context *Context) Flashes() []session.Message {
	return context.Auth.SessionStorer.Flashes(context.SessionManager())
}

// FormValue get form value with name
func (context *Context) FormValue(name string) string {
	return context.Request.Form.Get(name)
}

func (context *Context) Registrable() bool {
	return context.Auth.Registrable(context.Context)
}

func (context *Context) AuthPath(pth ...string) string {
	return context.Path(context.Auth.AuthPath(pth...))
}

func (context *Context) AuthURL(pth ...string) string {
	return context.Context.URL(context.Auth.AuthPath(pth...))
}

func (context *Context) AuthStaticURL(pth ...string) string {
	return context.JoinStaticURL(context.Auth.AuthPath(pth...))
}

func (context *Context) Set(values ...interface{}) {
	for _, value := range values {
		switch v := value.(type) {
		case *Auth:
			context.Auth = v
		case *claims.Claims:
			context.Claims = v
		}
	}
}

func (auth *Auth) NewContextFromRequest(r *http.Request, values ...interface{}) (*http.Request, *Context) {
	r, ctx := auth.ContextFactory.NewContextForRequest(r)
	c := &Context{Context: ctx, Auth: auth}
	c.Set(values...)
	return r, c
}

func (auth *Auth) NewContextFromRequestPair(w http.ResponseWriter, r *http.Request, values ...interface{}) (*http.Request, *Context) {
	r, ctx := auth.ContextFactory.NewContextFromRequestPair(w, r)
	c := &Context{Context: ctx, Auth: auth}
	c.Set(values...)
	return r, c
}

func (auth *Auth) NewContextFromSite(site *core.Site) *Context {
	ctx := auth.ContextFactory.NewSiteContext(site)
	c := &Context{Context: ctx, Auth: auth}
	return c
}
