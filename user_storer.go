package auth

import (
	"fmt"
	"reflect"

	"github.com/aghape/auth/auth_identity"
	"github.com/aghape/auth/claims"
	"github.com/aghape/core/utils"
	"github.com/jinzhu/copier"
	"github.com/moisespsena-go/aorm"
)

// UserStorerInterface user storer interface
type UserStorerInterface interface {
	Save(schema *Schema, context *Context) (user interface{}, userID string, err error)
	Get(claims *claims.Claims, context *Context) (user interface{}, err error)
}

// UserStorer default user storer
type UserStorer struct {
}

// Get defined how to get user with user id
func (UserStorer) Get(Claims *claims.Claims, context *Context) (user interface{}, err error) {
	var tx = context.DB

	if context.Auth.Config.UserModel != nil {
		if Claims.UserID != "" {
			currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
			if err = tx.First(currentUser, aorm.Key(Claims.UserID)).Error; err == nil {
				return currentUser, nil
			}
			return nil, ErrInvalidAccount
		}
	}

	var (
		authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		authInfo     = auth_identity.Basic{
			Provider: Claims.Provider,
			UID:      Claims.Id,
		}
	)

	if !tx.Where(authInfo).First(authIdentity).RecordNotFound() {
		if context.Auth.Config.UserModel != nil {
			if authBasicInfo, ok := authIdentity.(interface {
				ToClaims() *claims.Claims
			}); ok {
				currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
				if err = tx.First(currentUser, aorm.Key(authBasicInfo.ToClaims().UserID)).Error; err == nil {
					return currentUser, nil
				}
				return nil, ErrInvalidAccount
			}
		}

		return authIdentity, nil
	}

	return nil, ErrInvalidAccount
}

// Save defined how to save user
func (UserStorer) Save(schema *Schema, context *Context) (user interface{}, userID string, err error) {
	var db = context.DB

	if context.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)
		err = db.Create(currentUser).Error
		return currentUser, fmt.Sprint(db.NewScope(currentUser).PrimaryKeyValue()), err
	}
	return nil, "", nil
}
