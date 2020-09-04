package password

import (
	"html/template"
	"net/mail"
	"os"
	"time"

	"github.com/moisespsena-go/logging"
	path_helpers "github.com/moisespsena-go/path-helpers"

	"github.com/ecletus/auth/claims"

	"github.com/ecletus/auth/auth_identity/helpers"

	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/session"
	"github.com/moisespsena-go/aorm"
	zxcvbn_fb "github.com/moisespsena-go/zxcvbn-fb"
	"golang.org/x/crypto/bcrypt"
)

const DefaultStrengthLevel = 2

var log = logging.GetOrCreateLogger(path_helpers.GetCalledDir())

type PasswordUpdater struct {
	UID                         string
	Token                       string
	NewPassword                 string
	PasswordConfirm             string
	CurrentPassword             string
	CurrentPasswordDisabled     bool
	StrengthDisabled            bool
	StrengthLevel               int
	Createable                  bool
	Confirmed                   bool
	UserID                      string
	IsAdmin                     bool
	AdminUserUID                string
	AuthIdentityModel           interface{}
	Provider                    *Provider
	DB                          *aorm.DB
	T                           func(key string, defaul ...interface{}) string
	NotifyPlainPasswordDisabled bool
	NotifyMailer                UpdatedPasswordNotifier
	NotifyTo                    []mail.Address
	NotifyToUserDisabled        bool
}

func (this PasswordUpdater) Context(context *auth.Context) (Claims *claims.Claims, err error) {
	if this.CurrentPassword == "" && !this.CurrentPasswordDisabled {
		this.CurrentPassword =
			context.Request.Form.Get("current_password")
	}
	if this.NewPassword == "" {
		this.NewPassword = context.Request.Form.Get("new_password")
	}
	if this.PasswordConfirm == "" {
		this.PasswordConfirm = context.Request.Form.Get("password_confirm")
	}

	if this.AuthIdentityModel == nil {
		this.AuthIdentityModel = context.Auth.Config.AuthIdentityModel
	}

	if this.UID == "" {
		token := this.Token
		if token == "" {
			token = context.Request.Form.Get("reset_password_token")
		}
		if Claims, err = context.SessionStorer.ValidateClaims(token); err != nil {
			return nil, err
		} else if err = Claims.Valid(); err != nil {
			return nil, err
		} else {
			this.UID = Claims.Id
			this.UserID = Claims.UserID
		}
	}

	if this.Provider == nil {
		this.Provider, _ = context.Provider.(*Provider)
	}

	if this.DB == nil {
		this.DB = context.Site.GetSystemDB().DB
	}

	if this.T == nil {
		this.T = context.Ts
	}

	if err := this.Update(context); err != nil {
		return nil, err
	}
	_ = context.SessionStorer.Flash(context.SessionManager(), this.Success())
	return
}

func (this *PasswordUpdater) Success() session.Message {
	return session.Message{Message: template.HTML(this.T(ChangedPasswordFlashMessage)), Type: "success"}
}

func (this *PasswordUpdater) Update(context *auth.Context) (err error) {
	if this.NewPassword != this.PasswordConfirm {
		return ErrPasswordsNotMatch
	}

	if !this.StrengthDisabled && os.Getenv("AGHAPE_AUTH_PASSWORD_STRENGTH_DISABLED") != "true" {
		result, err := zxcvbn_fb.Zxcvbn(this.NewPassword)
		if err != nil {
			return ErrStrengthTestFailed
		}

		level := this.StrengthLevel
		if level == 0 {
			level = DefaultStrengthLevel
		}

		if result.Score < level {
			return ErrPasswordTooWeak
		}
	}

	var (
		identity auth_identity.AuthIdentityInterface
		authInfo *auth_identity.Basic
		provider = this.Provider
		DB       = this.DB
	)

	if identity, err = helpers.GetIdentity(this.AuthIdentityModel, provider.GetName(), DB, this.UID); err != nil {
		if err != auth.ErrInvalidAccount {
			return
		}

		if !this.Createable {
			return auth.ErrInvalidAccount
		}

		authInfo = &auth_identity.Basic{
			Provider: provider.GetName(),
			UID:      this.UID,
			UserID:   this.UserID,
		}

		if this.IsAdmin {
			authInfo.IsAdmin = true
		}

		if this.Confirmed {
			now := time.Now()
			authInfo.ConfirmedAt = &now
		}

		if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(this.NewPassword); err != nil {
			return err
		}

		identity = auth_identity.NewIdentityInterface(this.AuthIdentityModel)
		identity.SetAuthBasic(*authInfo)

		if err = DB.Model(identity).Create(identity).Error; err != nil {
			return ErrUserIdentityCreationFailed.Cause(err)
		}
		return nil
	}

	authInfo = identity.GetAuthBasic()
	if !this.CurrentPasswordDisabled {
		if this.CurrentPassword == "" {
			return ErrCurrentPasswordNotNatch
		}

		var currentInfo = authInfo

		if this.AdminUserUID != "" {
			currentInfo = &auth_identity.Basic{}
			currentInfo.Provider = provider.GetName()
			currentInfo.UID = this.AdminUserUID
			currentIdentity := auth_identity.NewIdentityInterface(this.AuthIdentityModel)

			if DB := DB.Model(this.AuthIdentityModel).Where(currentInfo).Scan(currentIdentity); DB.RecordNotFound() {
				return ErrAdminUserNotFound
			} else if DB.Error != nil {
				return ErrLoadAdminUserFailed.Cause(DB.Error)
			}
			currentInfo = currentIdentity.GetAuthBasic()
		}

		if err := provider.Encryptor.Compare(currentInfo.EncryptedPassword, this.CurrentPassword); err != nil {
			if err == bcrypt.ErrMismatchedHashAndPassword {
				return ErrCurrentPasswordNotNatch
			} else {
				return err
			}
		}
	}

	if authInfo.EncryptedPassword, err = provider.Encryptor.Digest(this.NewPassword); err == nil {
		// Confirm account after reset password, as user already click a link from email
		if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
			now := time.Now()
			authInfo.ConfirmedAt = &now
		}
		if err = helpers.SaveIdentity(DB, identity); err != nil {
			return err
		}
	}

	if this.NotifyMailer != nil {
		var (
			user   auth.User
			passwd string
		)
		if !this.NotifyPlainPasswordDisabled {
			passwd = this.NewPassword
		}
		if !this.NotifyToUserDisabled {
			user, err = context.Auth.UserStorer.Get(authInfo.ToClaims(), context)
			if err != nil {
				log.Warningf("PasswordUpdate.update@UserGetter failed: %v", err.Error())
				return nil
			}
		}
		if err := this.NotifyMailer.Notify(this.NotifyTo, context, user, passwd); err != nil {
			log.Warningf("PasswordUpdate.update@Notify failed: %v", err.Error())
			return nil
		}
	}

	return nil
}
