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
	FindFunc   func(context *Context, out interface{}, key aorm.KeyInterface) error
	CreateFunc func(context *Context, out interface{}) error
}

// Get defined how to get user with user id
func (us UserStorer) Get(Claims *claims.Claims, context *Context) (user interface{}, err error) {
	var tx = context.DB

	if context.Auth.Config.UserModel != nil {
		if Claims.UserID != "" {
			var (
				currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
				key         = aorm.Key(Claims.UserID)
			)
			if us.FindFunc != nil {
				err = us.FindFunc(context, currentUser, key)
			} else {
				err = tx.First(currentUser, key).Error
			}
			if err == nil {
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
				var (
					currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
					key         = aorm.Key(authBasicInfo.ToClaims().UserID)
				)
				if us.FindFunc != nil {
					err = us.FindFunc(context, currentUser, key)
				} else {
					err = tx.First(currentUser, key).Error
				}

				if err == nil {
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
func (us UserStorer) Save(schema *Schema, context *Context) (user interface{}, userID string, err error) {
	var db = context.DB

	if context.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)
		if us.CreateFunc != nil {
			err = us.CreateFunc(context, currentUser)
		} else {
			err = db.Create(currentUser).Error
		}
		return currentUser, fmt.Sprint(db.NewScope(currentUser).PrimaryKeyValue()), err
	}
	return nil, "", nil
}
