package authority

import (
	"time"

	"github.com/aghape/core"
	"github.com/aghape/core/utils"
	"github.com/moisespsena/go-route"
)

// ClaimsContextKey authority claims key
var ClaimsContextKey utils.ContextKey = "authority_claims"

// Middleware authority middleware used to record activity time
func (authority *Authority) Middleware() *route.Middleware {
	return &route.Middleware{
		Name:  "qor:authority",
		After: []string{"qor:session"},
		Handler: func(chain *route.ChainHandler) {
			context := core.ContexFromChain(chain)
			sm := context.SessionManager()
			if claims, err := authority.Auth.Get(sm); err == nil {
				var zero time.Duration

				lastActiveAt := claims.LastActiveAt
				if lastActiveAt != nil {
					lastDistractionTime := time.Now().Sub(*lastActiveAt)
					if claims.LongestDistractionSinceLastLogin == nil || *claims.LongestDistractionSinceLastLogin < lastDistractionTime {
						claims.LongestDistractionSinceLastLogin = &lastDistractionTime
					}

					if claims.LastLoginAt != nil {
						if claims.LastLoginAt.After(*claims.LastActiveAt) {
							claims.LongestDistractionSinceLastLogin = &zero
						} else if loggedDuration := claims.LastActiveAt.Sub(*claims.LastLoginAt); *claims.LongestDistractionSinceLastLogin > loggedDuration {
							claims.LongestDistractionSinceLastLogin = &loggedDuration
						}
					}
				} else {
					claims.LongestDistractionSinceLastLogin = &zero
				}

				now := time.Now()
				claims.LastActiveAt = &now

				authority.Auth.Update(sm, claims)
			}

			chain.Pass()
		},
	}
}
