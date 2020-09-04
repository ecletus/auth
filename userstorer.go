package auth

import (
	"reflect"

	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core/utils"
	"github.com/jinzhu/copier"
	"github.com/moisespsena-go/aorm"
)

type User interface {
	Schema() *Schema
}

// UserStorerInterface user storer interface
type UserStorerInterface interface {
	Save(schema *Schema, context *Context) (user User, userId aorm.ID, err error)
	Get(claims *claims.Claims, context *Context) (user User, err error)
}

// UserStorer default user storer
type UserStorer struct {
	FindFunc   func(context *Context, out interface{}, key aorm.ID) error
	CreateFunc func(context *Context, out interface{}) error
}

// Get defined how to get user with user id
func (us UserStorer) Get(Claims *claims.Claims, context *Context) (user User, err error) {
	var db = context.DB()

	if context.Auth.Config.UserModel != nil {
		if Claims.UserID != "" {
			var (
				currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
				key         aorm.ID
			)
			if key, err = aorm.StructOf(currentUser).ParseIDString(Claims.UserID); err != nil {
				return
			}
			if us.FindFunc != nil {
				err = us.FindFunc(context, currentUser, key)
			} else {
				err = db.First(currentUser, key).Error
			}
			if err == nil {
				return currentUser.(User), nil
			}
			if aorm.IsRecordNotFoundError(err) {
				return nil, ErrInvalidAccount
			}
			return
		}
	}

	var (
		authIdentity = reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		authInfo     = auth_identity.Basic{
			Provider: Claims.Provider,
			UID:      Claims.Id,
		}
	)

	if !db.Where(authInfo).First(authIdentity).RecordNotFound() {
		if context.Auth.Config.UserModel != nil {
			if authBasicInfo, ok := authIdentity.(interface {
				ToClaims() *claims.Claims
			}); ok {
				var (
					currentUser = reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
					key         aorm.ID
					err         error
				)
				if key, err = db.NewScope(context.Auth.Config.UserModel).Struct().ParseIDString(authBasicInfo.ToClaims().UserID); err != nil {
					return nil, err
				}
				if us.FindFunc != nil {
					err = us.FindFunc(context, currentUser, key)
				} else {
					err = db.First(currentUser, key).Error
				}

				if err == nil {
					return currentUser.(User), nil
				}
				return nil, err
			}
		}

		return &identityUser{authIdentity.(auth_identity.AuthIdentityInterface)}, nil
	}

	return nil, ErrInvalidAccount
}

// Save defined how to save user
func (us UserStorer) Save(schema *Schema, context *Context) (user User, userID aorm.ID, err error) {
	var db = context.DB()

	if context.Auth.Config.UserModel != nil {
		currentUser := reflect.New(utils.ModelType(context.Auth.Config.UserModel)).Interface()
		copier.Copy(currentUser, schema)
		if us.CreateFunc != nil {
			err = us.CreateFunc(context, currentUser)
		} else {
			err = db.Create(currentUser).Error
		}
		return currentUser.(User), aorm.IdOf(currentUser), err
	}
	return
}

type identityUser struct {
	auth_identity.AuthIdentityInterface
}

func (this identityUser) Schema() *Schema {
	basic := this.GetAuthBasic()
	return &Schema{
		Provider: basic.Provider,
		UID:      basic.UID,
		RawInfo:  this,
	}
}
