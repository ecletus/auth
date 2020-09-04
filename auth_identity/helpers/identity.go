package helpers

import (
	"reflect"

	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/core/utils"
	"github.com/moisespsena-go/aorm"
)

func NewIdentity(authIdentityModel interface{}, providerName string) (identity auth_identity.AuthIdentityInterface) {
	identity = reflect.New(utils.ModelType(authIdentityModel)).Interface().(auth_identity.AuthIdentityInterface)
	authInfo := &auth_identity.Basic{}
	authInfo.Provider = providerName
	identity.SetAuthBasic(*authInfo)
	return identity
}

func GetIdentity(authIdentityModel interface{}, providerName string, DB *aorm.DB, uid string) (identity auth_identity.AuthIdentityInterface, err error) {
	authInfo := &auth_identity.Basic{}
	authInfo.Provider = providerName
	authInfo.UID = uid
	identity = reflect.New(utils.ModelType(authIdentityModel)).Interface().(auth_identity.AuthIdentityInterface)

	if err = DB.Model(authIdentityModel).Where(authInfo).Scan(identity).Error; aorm.IsRecordNotFoundError(err) {
		return nil, auth.ErrInvalidAccount
	} else if err != nil {
		return nil, err
	}

	return identity, nil
}

func SaveIdentity(DB *aorm.DB, identity auth_identity.AuthIdentityInterface) error {
	return DB.Model(identity).Save(identity).Error
}

func DeleteIdentity(DB *aorm.DB, identity auth_identity.AuthIdentityInterface) error {
	return DB.Model(identity).Delete(identity).Error
}
