package authority

import (
	"time"

	claims2 "github.com/ecletus/auth/claims"
	"github.com/moisespsena-go/aorm"

	"github.com/dgrijalva/jwt-go"
	"github.com/ecletus/session"
	"github.com/moisespsena/template/html/template"

	"net/http"

	"github.com/ecletus/auth"
	"github.com/ecletus/core"
	"github.com/ecletus/core/utils"
	"github.com/moisespsena-go/xroute"
)

// ClaimsContextKey authority claims key
var ClaimsContextKey utils.ContextKey = "authority_claims"

// Middleware authority middleware used to record activity time
func (authority *Authority) Middleware() *xroute.Middleware {
	return &xroute.Middleware{
		Name:  "qor:authority",
		After: []string{"qor:session"},
		Handler: func(chain *xroute.ChainHandler) {
			context := core.ContextFromRequest(chain.Request())
			context.Role.Register(authority.Role.Descriptors()...)

			sm := context.SessionManager()
			var (
				Claims *claims2.Claims
				err    error
			)

			if Claims, err = authority.Auth.Get(sm); err == auth.ErrNoSession {
				if token := context.Request.Header.Get("Authorization"); token != "" {
					if Claims, err = authority.Auth.ValidateClaims(token); err != nil {
						http.Error(context.Writer, err.Error(), http.StatusBadRequest)
						return
					}
					if err = authority.Auth.Signed(context, Claims); err != nil {
						if aorm.IsRecordNotFoundError(err) {
							http.Error(context.Writer, "unknown identity", http.StatusUnauthorized)
							return
						}
						if err == auth.ErrMaximumNumberOfAccessesReached {
							http.Error(context.Writer, err.Error(), http.StatusForbidden)
							return
						}
						http.Error(context.Writer, err.Error(), http.StatusInternalServerError)
						return
					}
				}
			}
			if err != nil {
				if _, ok := err.(*jwt.ValidationError); ok {
					authority.Auth.Delete(context.SessionManager())
					err = context.SessionManager().Flash(session.Message{template.HTML(err.Error()), "error"})
					if err = authority.Auth.Delete(sm); err == nil {
						http.Redirect(chain.Writer, chain.Request(), context.OriginalURL.String(), http.StatusSeeOther)
						return
					}
					if err != nil {
						http.Error(chain.Writer, err.Error(), http.StatusInternalServerError)
					}
					return
				}
				if err != auth.ErrNoSession {
					http.Error(chain.Writer, err.Error(), http.StatusInternalServerError)
					return
				}
			} else {
				var (
					zero         time.Duration
					lastActiveAt = Claims.LastActiveAt
				)

				if lastActiveAt != nil {
					lastDistractionTime := time.Now().Sub(*lastActiveAt)
					if Claims.LongestDistractionSinceLastLogin == nil || *Claims.LongestDistractionSinceLastLogin < lastDistractionTime {
						Claims.LongestDistractionSinceLastLogin = &lastDistractionTime
					}

					if Claims.LastLoginAt != nil {
						if Claims.LastLoginAt.After(*Claims.LastActiveAt) {
							Claims.LongestDistractionSinceLastLogin = &zero
						} else if loggedDuration := Claims.LastActiveAt.Sub(*Claims.LastLoginAt); *Claims.LongestDistractionSinceLastLogin > loggedDuration {
							Claims.LongestDistractionSinceLastLogin = &loggedDuration
						}
					}
				} else {
					Claims.LongestDistractionSinceLastLogin = &zero
				}

				authority.Auth.Update(sm, Claims)

				_, err := authority.Auth.GetCurrentUser(context.Request)
				if err != nil {
					if err == auth.ErrInvalidAccount {
						authority.Auth.Delete(sm)
						http.Error(chain.Writer, err.Error(), http.StatusForbidden)
						return
					}
					http.Error(chain.Writer, err.Error(), http.StatusInternalServerError)
					return
				}
			}

			chain.Next()
		},
	}
}
