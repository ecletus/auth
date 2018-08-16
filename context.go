package auth

import (
	"net/http"

	"github.com/aghape/auth/claims"
	"github.com/aghape/session"
	"github.com/aghape/aghape"
)

// Context context
type Context struct {
	*qor.Context
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

func (context *Context) Set(values... interface{})  {
	for _, value := range values {
		switch v := value.(type) {
		case *Auth:
			context.Auth = v
		case *claims.Claims:
			context.Claims = v
		}
	}
}

func NewContextFromRequest(r *http.Request, values... interface{}) (*http.Request, *Context) {
	r, ctx := qor.NewContextForRequest(r)
	c := &Context{Context: ctx}
	c.Set(values...)
	return r, c
}

func NewContextFromRequestPair(w http.ResponseWriter, r *http.Request, values... interface{}) (*http.Request, *Context) {
	r, ctx := qor.NewContextFromRequestPair(w, r)
	c := &Context{Context: ctx}
	c.Set(values...)
	return r, c
}