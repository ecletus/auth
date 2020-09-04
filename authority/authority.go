package authority

import (
	"net/http"

	"github.com/moisespsena-go/path-helpers"
	"github.com/op/go-logging"

	"github.com/ecletus/auth"
	"github.com/ecletus/common"
	"github.com/ecletus/core"
	"github.com/ecletus/roles"
	"github.com/ecletus/session"
	_ "github.com/ecletus/session/manager"
	"github.com/moisespsena/template/html/template"
)

var (
	log = logging.MustGetLogger(path_helpers.GetCalledDir())

	// AccessDeniedFlashMessage access denied message
	AccessDeniedFlashMessage = template.HTML("Access Denied!")
)

// Authority authority struct
type Authority struct {
	*Config
}

// AuthInterface auth interface
type AuthInterface interface {
	auth.SessionStorerInterface
	auth.SignedCallbacker

	GetCurrentUser(req *http.Request) (user common.User, err error)
}

// Config authority config
type Config struct {
	Auth                AuthInterface
	Role                *roles.Role
	AccessDeniedHandler func(w http.ResponseWriter, req *http.Request)
}

// New initialize Authority
func New(config *Config) *Authority {
	if config == nil {
		config = &Config{}
	}

	if config.Auth == nil {
		panic("Auth should not be nil for Authority")
	}

	if config.Role == nil {
		config.Role = &roles.Role{}
	}

	if config.AccessDeniedHandler == nil {
		config.AccessDeniedHandler = NewAccessDeniedHandler(config.Auth, "/")
	}

	return &Authority{Config: config}
}

// Authorize authorize specfied roles or authenticated user to access wrapped handler
func (authority *Authority) Authorize(roles ...string) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			// Get current user from request
			currentUser, err := authority.Auth.GetCurrentUser(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if (len(roles) == 0 && currentUser != nil) || authority.Role.HasRole(req, currentUser, roles...) {
				handler.ServeHTTP(w, req)
				return
			}

			authority.AccessDeniedHandler(w, req)
		})
	}
}

// NewAccessDeniedHandler new access denied handler
func NewAccessDeniedHandler(Auth AuthInterface, redirectPath string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		Auth.Flash(core.ContextFromRequest(req).SessionManager(), session.Message{Message: AccessDeniedFlashMessage})
		http.Redirect(w, req, redirectPath, http.StatusSeeOther)
	}
}
