package auth

import (
	"net/http"

	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core"
	"github.com/ecletus/session"
)

// Context context
type Context struct {
	*core.Context
	*Auth
	Claims   *claims.Claims
	Provider Provider
}

// Flashes get flash messages
func (context Context) Flashes() []session.Message {
	return context.Auth.SessionStorer.Flashes(context.SessionManager())
}

// FormValue get form value with name
func (context Context) FormValue(name string) string {
	return context.Request.Form.Get(name)
}

func (context *Context) Registrable() bool {
	return context.Auth.Registrable(context.Context)
}

func (context *Context) AuthURL(path string) string {
	return context.GenURL(context.Auth.AuthURL(path))
}

func (context *Context) AuthStaticURL(path string) string {
	return context.GenStaticURL(context.Auth.AuthURL(path))
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
