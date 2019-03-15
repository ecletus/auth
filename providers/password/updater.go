package password

import (
	"errors"
	"fmt"
	"html/template"
	"os"
	"reflect"
	"time"

	"github.com/aghape/auth"
	"github.com/aghape/auth/auth_identity"
	"github.com/aghape/core/utils"
	"github.com/aghape/session"
	"github.com/moisespsena-go/aorm"
	"github.com/moisespsena-go/zxcvbn-fb"
	"github.com/moisespsena/go-error-wrap"
	"golang.org/x/crypto/bcrypt"
)

type PasswordUpdater struct {
	UID                     string
	Token                   string
	NewPassword             string
	PasswordConfirm         string
	CurrentPassword         string
	CurrentPasswordDisabled bool
	StrengthDisabled        bool
	Createable              bool
	Confirmed               bool
	UserID                  string
	AdminUserUID            string
	AuthIdentityModel       interface{}
	Provider                *Provider
	DB                      *aorm.DB
	T                       func(key string, defaul ...interface{}) string
}

func (pu PasswordUpdater) Context(context *auth.Context) error {
	if pu.CurrentPassword == "" && !pu.CurrentPasswordDisabled {
		pu.CurrentPassword =
			context.Request.Form.Get("current_password")
	}
	if pu.NewPassword == "" {
		pu.NewPassword = context.Request.Form.Get("new_password")
	}
	if pu.PasswordConfirm == "" {
		pu.PasswordConfirm = context.Request.Form.Get("password_confirm")
	}

	if pu.AuthIdentityModel == nil {
		pu.AuthIdentityModel = context.Auth.Config.AuthIdentityModel
	}

	if pu.UID == "" {
		token := pu.Token
		if token == "" {
			token = context.Request.Form.Get("reset_password_token")
		}

		if claims, err := context.SessionStorer.ValidateClaims(token); err != nil {
			return err
		} else if err = claims.Valid(); err != nil {
			return err
		} else {
			pu.UID = claims.Id
			pu.UserID = claims.UserID
		}
	}

	if pu.Provider == nil {
		pu.Provider, _ = context.Provider.(*Provider)
	}

	if pu.DB == nil {
		pu.DB = context.Site.GetSystemDB().DB
	}

	if pu.T == nil {
		pu.T = context.Ts
	}

	if err := pu.Update(); err != nil {
		return err
	}
	_ = context.SessionStorer.Flash(context.SessionManager(), pu.Success())
	return nil
}

func (pu *PasswordUpdater) Success() session.Message {
	return session.Message{Message: template.HTML(pu.T(ChangedPasswordFlashMessage)), Type: "success"}
}

func (pu *PasswordUpdater) Update() (err error) {
	var (
		authInfo = &auth_identity.Basic{}
		DB       = pu.DB
		id       = pu.UID
		provider = pu.Provider
	)

	if pu.NewPassword != pu.PasswordConfirm {
		return errors.New(pu.T(auth.I18n("passwords.passwords_not_match")))
	}

	if !pu.StrengthDisabled && os.Getenv("AGHAPE_AUTH_PASSWORD_STRENGTH_DISABLED") != "true" {
		result, err := zxcvbn_fb.Zxcvbn(pu.NewPassword)
		if err != nil {
			return errwrap.Wrap(err, pu.T(auth.I18n("passwords.strength_test_failed")))
		}

		if result.Score < 3 {
			return errors.New(pu.T(auth.I18n("passwords.password_too_weak")))
		}
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = id
	authIdentity := reflect.New(utils.ModelType(pu.AuthIdentityModel)).Interface().(auth_identity.AuthIdentityInterface)

	if DB.Model(pu.AuthIdentityModel).Where(authInfo).Scan(authIdentity).RecordNotFound() {
		if !pu.Createable {
			return auth.ErrInvalidAccount
		}

		authInfo.UserID = pu.UserID

		if pu.Confirmed {
			now := time.Now()
			authInfo.ConfirmedAt = &now
		}

		if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(pu.NewPassword); err != nil {
			return err
		}

		authIdentity.SetAuthBasic(*authInfo)

		if err = DB.Model(authIdentity).Create(authIdentity).Error; err != nil {
			return errwrap.Wrap(err, pu.T(auth.I18n("passwords.create_user_identity")))
		}
		return nil
	}

	authInfo = authIdentity.GetAuthBasic()
	if !pu.CurrentPasswordDisabled {
		if pu.CurrentPassword == "" {
			return errors.New(pu.T(auth.I18n("form.current_password_placeholder")))
		}

		var localAuthInfo = authInfo

		if pu.AdminUserUID != "" {
			localAuthInfo = &auth_identity.Basic{}
			localAuthInfo.Provider = provider.GetName()
			localAuthInfo.UID = pu.AdminUserUID
			localAuthIdentity := reflect.New(utils.ModelType(pu.AuthIdentityModel)).Interface().(auth_identity.AuthIdentityInterface)

			DB := DB.Model(pu.AuthIdentityModel).Where(localAuthInfo).Scan(localAuthIdentity)
			if DB.Error != nil {
				return errwrap.Wrap(err, pu.T(auth.I18n("passwords.load_admin_user_failed")))
			} else if DB.RecordNotFound() {
				return errwrap.Wrap(err, pu.T(auth.I18n("passwords.admin_user_not_found")))
			}
			localAuthInfo = localAuthIdentity.GetAuthBasic()
		}

		if err := provider.Encryptor.Compare(localAuthInfo.EncryptedPassword, pu.CurrentPassword); err != nil {
			if err == bcrypt.ErrMismatchedHashAndPassword {
				return fmt.Errorf(pu.T(auth.I18n("passwords.current_password_not_match")))
			} else {
				return err
			}
		}
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(pu.NewPassword); err == nil {
		// Confirm account after reset password, as user already click a link from email
		if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
			now := time.Now()
			authInfo.ConfirmedAt = &now
		}
		if err = DB.Model(authIdentity).Save(authIdentity).Error; err != nil {
			return err
		}
	}
	return nil
}
