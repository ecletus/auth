package auth

import (
	"net/http"
	"time"

	"github.com/aghape/auth/claims"
	"github.com/aghape/common"
	"github.com/aghape/core"
	"github.com/aghape/core/utils"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "qor:auth.current_user"

// GetCurrentUser get current user from request
func (auth *Auth) GetCurrentUser(req *http.Request) (currentUser common.User) {
	qorContext := core.ContextFromRequest(req).Top()

	if currentUser = qorContext.CurrentUser(); currentUser != nil {
		return currentUser
	}

	defer func() {
		if currentUser != nil {
			qorContext.SetCurrentUser(currentUser)
		}
	}()

	if user := qorContext.Data().Get(CurrentUser); user != nil {
		return user.(common.User)
	}

	claims, err := auth.SessionStorer.Get(qorContext.SessionManager())
	if err == nil {
		_, context := auth.NewContextFromRequest(req, auth, claims)
		if user, err := auth.UserStorer.Get(claims, context); err == nil {
			qorContext.Data().Set(CurrentUser, user)
			currentUser = user.(common.User)
		}
	}

	return
}

func (auth *Auth) InterceptFunc(w http.ResponseWriter, r *http.Request, f func()) {
	if auth.GetCurrentUser(r) == nil {
		auth.URL(r).LoginPage(true)
		return
	}
	f()
}

func (auth *Auth) Intercept(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	auth.InterceptFunc(w, r, func() {
		handler.ServeHTTP(w, r)
	})
}

// Login sign user in
func (auth *Auth) Login(w http.ResponseWriter, r *http.Request, claimer claims.ClaimerInterface) error {
	claims := claimer.ToClaims()
	now := time.Now()
	claims.LastLoginAt = &now

	return auth.SessionStorer.Update(core.ContextFromRequest(r).SessionManager(), claims)
}

// Logout sign current user out
func (auth *Auth) Logout(w http.ResponseWriter, req *http.Request) {
	auth.SessionStorer.Delete(core.ContextFromRequest(req).SessionManager())
}

func InterceptFuncIfAuth(authp interface{}, w http.ResponseWriter, r *http.Request, f func(bool)) {
	var (
		auth *Auth
		ok   bool
	)

	if authp != nil {
		if auth, ok = authp.(*Auth); !ok {
			if authg, ok := authp.(interface {
				Auth() *Auth
			}); ok {
				auth = authg.Auth()
			} else {
				panic("Invalid <authp> param,")
			}
		}
	}

	if auth != nil {
		auth.InterceptFunc(w, r, func() {
			f(true)
		})
	} else {
		f(false)
	}
}
