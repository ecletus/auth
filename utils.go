package auth

import (
	"net/http"
	"time"

	"github.com/qor/qor"
	"github.com/qor/auth/claims"
	"github.com/qor/qor/utils"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "current_user"

// GetCurrentUser get current user from request
func (auth *Auth) GetCurrentUser(req *http.Request) interface{} {
	qorContext := qor.ContextFromRequest(req).GetTop()

	if currentUser := qorContext.Data().Get(CurrentUser); currentUser != nil {
		return currentUser
	}

	claims, err := auth.SessionStorer.Get(qorContext.SessionManager())
	if err == nil {
		_, context := NewContextFromRequest(req, auth, claims)
		if user, err := auth.UserStorer.Get(claims, context); err == nil {
			return user
		}
	}

	return nil
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

	return auth.SessionStorer.Update(qor.ContextFromRequest(r).SessionManager(), claims)
}

// Logout sign current user out
func (auth *Auth) Logout(w http.ResponseWriter, req *http.Request) {
	auth.SessionStorer.Delete(qor.ContextFromRequest(req).SessionManager())
}



func InterceptFuncIfAuth(authp interface{}, w http.ResponseWriter, r *http.Request, f func(bool)) {
	var (
		auth *Auth
		ok bool
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