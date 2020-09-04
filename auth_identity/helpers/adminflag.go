package helpers

import (
	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/moisespsena-go/aorm"
)

func SetAdminFlag(authIdentityModel interface{}, provider auth.Provider, DB *aorm.DB, uid string, to bool) (err error) {
	var identity auth_identity.AuthIdentityInterface
	if identity, err = GetIdentity(authIdentityModel, provider.GetName(), DB, uid); err != nil {
		return
	}

	identity.GetAuthBasic().IsAdmin = to
	return DB.Model(identity).Save(identity).Error
}
