package auth

import (
	"net/http"

	"github.com/aghape/redirect_back"
	"github.com/moisespsena/go-route"
)

// RedirectorInterface redirector interface
type RedirectorInterface interface {
	// Redirect redirect after action
	Redirect(w http.ResponseWriter, req *http.Request, action string)
	Middleware() *route.Middleware
}

// Redirector default redirector
type Redirector struct {
	*redirect_back.RedirectBack
}

// Redirect redirect back after action
func (redirector Redirector) Redirect(w http.ResponseWriter, req *http.Request, action string) {
	redirector.RedirectBack.RedirectBack(w, req)
}
