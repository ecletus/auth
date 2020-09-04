package auth

import (
	"net/http"

	"github.com/ecletus/redirect_back"
	"github.com/moisespsena-go/xroute"
)

// RedirectorInterface redirector interface
type RedirectorInterface interface {
	// Redirect redirect after action
	Redirect(w http.ResponseWriter, req *http.Request, action string)
	Middleware() *xroute.Middleware
}

// Redirector default redirector
type Redirector struct {
	*redirect_back.RedirectBack
}

// Redirect redirect back after action
func (redirector Redirector) Redirect(w http.ResponseWriter, req *http.Request, action string) {
	redirector.RedirectBack.RedirectBack(w, req, action)
}
