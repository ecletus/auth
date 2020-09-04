package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/ecletus/auth/claims"
	"github.com/ecletus/common"
	"github.com/ecletus/core"
	"github.com/ecletus/core/utils"
	"github.com/ecletus/responder"
	"github.com/ecletus/session"
)

// CurrentUser context key to get current user from Request
const CurrentUser utils.ContextKey = "qor:auth.current_user"

// GetCurrentUser get current user from request
func (auth *Auth) GetCurrentUser(req *http.Request) (currentUser common.User, err error) {
	qorContext := core.ContextFromRequest(req)

	if currentUser = qorContext.CurrentUser(); currentUser != nil {
		return currentUser, nil
	}

	defer func() {
		if currentUser != nil {
			qorContext.SetCurrentUser(currentUser)
		}
	}()

	user := qorContext.Value(CurrentUser)
	if user != nil {
		return user.(common.User), nil
	}

	Claims, err := auth.SessionStorer.Get(qorContext.SessionManager())
	if err == nil {
		_, context := auth.NewContextFromRequest(req, auth, Claims)
		if user, err = auth.UserStorer.Get(Claims, context); err == nil {
			qorContext.SetValue(CurrentUser, user)
			currentUser = user.(common.User)
		}
	}
	return nil, err
}

// GetCurrentUserClaims get current user and Claims from request
func (auth *Auth) GetCurrentUserClaims(req *http.Request) (currentUser common.User, Claims *claims.Claims, err error) {
	qorContext := core.ContextFromRequest(req).Top()

	if Claims, err = auth.SessionStorer.Get(qorContext.SessionManager()); err != nil {
		return
	}

	if currentUser = qorContext.CurrentUser(); currentUser != nil {
		return
	}

	defer func() {
		if currentUser != nil {
			qorContext.SetCurrentUser(currentUser)
		}
	}()

	user := GetUserI(qorContext)
	if user != nil {
		currentUser = user.(common.User)
		return
	}

	_, context := auth.NewContextFromRequest(req, auth, Claims)
	if user, err = auth.UserStorer.Get(Claims, context); err == nil {
		qorContext.SetValue(CurrentUser, user)
		currentUser = user.(common.User)
	} else {
		Claims = nil
	}
	return
}

func (auth *Auth) InterceptFunc(w http.ResponseWriter, r *http.Request, f func()) {
	if user, err := auth.GetCurrentUser(r); user != nil {
		f()
		return
	} else if err != nil && err != ErrNoSession {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	auth.URL(r).LoginReturn()
}

func (auth *Auth) Intercept(w http.ResponseWriter, r *http.Request, handler http.Handler) {
	auth.InterceptFunc(w, r, func() {
		handler.ServeHTTP(w, r)
	})
}

// Login sign user in
func (auth *Auth) Signed(ctx *core.Context, Claims *claims.Claims) (err error) {
	now := time.Now().UTC()
	Claims.LastLoginAt = &now
	if cb, ok := auth.AuthIdentityModel.(SignedCallbacker); ok {
		return cb.Signed(ctx, Claims)
	}
	for _, f := range auth.signedCallbacks {
		if err = f(ctx, Claims); err != nil {
			return
		}
	}
	return nil
}

// Login sign user in
func (auth *Auth) FindUID(ctx *Context, identifier string) (uid string, err error) {
	if uid, err = auth.UIDFinders.FindUID(ctx, identifier); uid != "" || (err != nil && err != ErrInvalidAccount) {
		return
	}
	if finder, ok := auth.UserModel.(UIDFinder); ok {
		uid, err = finder.FindUID(ctx, identifier)
		return
	}
	err = ErrInvalidAccount
	return
}

// Login sign user in
func (auth *Auth) Login(ctx *LoginContext) (Claims *claims.Claims, err error) {
	if err = ctx.Provider.PrepareLoginContext(ctx); err != nil {
		return nil, err
	}

	if cb, ok := auth.UserModel.(AuthInfor); ok {
		ctx.InfoCallbacks = append([]InfoCallback{cb.AuthInfo}, ctx.InfoCallbacks...)
	}

	// TODO: Not used
	ctx.InfoCallbacks = append(auth.LoginCallbacks.InfoCallbacks[:], ctx.InfoCallbacks...)

	ctx.ErrorCallbacks = append(auth.LoginCallbacks.ErrorCallbacks[:], ctx.ErrorCallbacks...)

	if cb, ok := auth.UserModel.(AuthBeforer); ok {
		if err = cb.BeforeAuth(ctx); err != nil {
			return
		}
	}
	for _, f := range auth.LoginCallbacks.BeforeLoginCallbacks {
		if err = f(ctx); err != nil {
			return
		}
	}
	for _, f := range ctx.BeforeLoginCallbacks {
		if err = f(ctx); err != nil {
			return
		}
	}

	Claims, err = ctx.Login()

	if err == nil {
		if cb, ok := auth.UserModel.(AuthLoggeder); ok {
			if err = cb.AuthLogged(ctx, Claims); err != nil {
				return
			}
		}

		for _, f := range auth.LoginCallbacks.LoggedCallbacks {
			if err = f(ctx, Claims); err != nil {
				return
			}
		}
		for _, f := range ctx.LoggedCallbacks {
			if err = f(ctx, Claims); err != nil {
				return
			}
		}

		if err = auth.SessionStorer.Update(ctx.SessionManager(), Claims); err != nil {
			return
		}

		if !ctx.Silent {
			responder.With("html", func() {
				err = ctx.SessionStorer.Flash(ctx.SessionManager(), session.Message{Message: "logged"})
			}).With([]string{"json"}, func() {
			}).Respond(ctx.Request)
		}
		respond(ctx, Claims, auth.LoginPageRedirectTo)
	} else {
		for _, f := range ctx.ErrorCallbacks {
			f(ctx, err)
		}
		if !ctx.SilentError {
			respond(ctx, nil, auth.LoginPageRedirectTo)
		}
	}
	return
}

// Logout sign current user out
func (auth *Auth) Logout(w http.ResponseWriter, req *http.Request) {
	auth.SessionStorer.Delete(core.ContextFromRequest(req).SessionManager())
}

func Authenticates(authp interface{}, w http.ResponseWriter, r *http.Request, f func(bool)) {
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

func GetUserI(ctx context.Context) interface{} {
	return ctx.Value(CurrentUser)
}

func GetUser(ctx context.Context) common.User {
	if user := ctx.Value(CurrentUser); user != nil {
		return user.(common.User)
	}
	return nil
}
