package password

import (
	"github.com/ecletus/auth/auth_identity/helpers"
	"github.com/moisespsena-go/aorm"
	"reflect"
	"strings"

	"github.com/ecletus/auth"
	"github.com/ecletus/auth/auth_identity"
	"github.com/ecletus/auth/claims"
	"github.com/ecletus/core/utils"
	"github.com/ecletus/session"
)

// DefaultAuthorizeHandler default authorize handler
var DefaultAuthorizeHandler = func(ctx *auth.LoginContext) (Claims *claims.Claims, err error) {
	var (
		authInfo    auth_identity.Basic
		identity auth_identity.AuthIdentityInterface
		db          = ctx.DB()
		provider, _ = ctx.Provider.(*Provider)
		uid         = ctx.UID
		password    = ctx.LoginData[FieldPassword].(string)
	)

	if uid == "" {
		if uid, err = ctx.Auth.FindUID(ctx.Context, ctx.LoginData[FieldLogin].(string)); err != nil {
			return
		} else if uid == "" {
			return nil, auth.ErrUidBlank
		}
	}

	if identity, err = helpers.GetIdentity(ctx.Auth.AuthIdentityModel, ctx.Provider.GetName(), db, uid); err != nil {
		return
	}

	authInfo = *identity.GetAuthBasic()

	if provider.Config.Confirmable && authInfo.ConfirmedAt == nil {
		currentUser, _ := ctx.Auth.UserStorer.Get(authInfo.ToClaims(), ctx.Context)
		provider.Config.ConfirmMailer(authInfo.UID, ctx.Context, authInfo.ToClaims(), currentUser)

		return nil, ErrUnconfirmed
	}

	for _, f := range ctx.InfoCallbacks {
		if err = f(ctx, &authInfo); err != nil {
			return
		}
	}

	if err = provider.Encryptor.Compare(string(authInfo.EncryptedPassword), password); err == nil {
		return authInfo.ToClaims(), nil
	}

	return nil, ErrPasswordsNotMatch
}

// DefaultRegisterHandler default register handler
var DefaultRegisterHandler = func(context *auth.Context) (Claims *claims.Claims, err error) {
	var (
		currentUser interface{}
		schema      auth.Schema
		authInfo    auth_identity.Basic
		req         = context.Request
		db          = context.DB()
		provider, _ = context.Provider.(*Provider)
	)

	if err = req.ParseForm(); err != nil {
		return
	}

	if req.Form.Get("login") == "" {
		return nil, auth.ErrInvalidAccount
	}

	if req.Form.Get("password") == "" {
		return nil, auth.ErrInvalidPassword
	}

	authInfo.Provider = provider.GetName()
	authInfo.UID = strings.TrimSpace(req.Form.Get("login"))

	if !db.Model(context.Auth.AuthIdentityModel).Where(authInfo).Scan(&authInfo).RecordNotFound() {
		return nil, auth.ErrInvalidAccount
	}

	var ep string
	if ep, err = provider.Encryptor.Digest(strings.TrimSpace(req.Form.Get("password"))); err == nil {
		authInfo.EncryptedPassword = aorm.ProtectedString(ep)
		schema.Provider = authInfo.Provider
		schema.UID = authInfo.UID
		schema.Email = authInfo.UID
		schema.RawInfo = req
		var userId aorm.ID
		currentUser, userId, err = context.Auth.UserStorer.Save(&schema, context)
		authInfo.UserID = userId.String()
		if err != nil {
			return nil, err
		}

		// create auth identity
		authIdentity := reflect.New(utils.ModelType(context.Auth.Config.AuthIdentityModel)).Interface()
		if err = db.Where(authInfo).FirstOrCreate(authIdentity).Error; err == nil {
			if provider.Config.Confirmable {
				context.SessionStorer.Flash(context.SessionManager(), session.Message{Message: ConfirmFlashMessage, Type: "success"})
				err = provider.Config.ConfirmMailer(schema.Email, context, authInfo.ToClaims(), currentUser)
			}

			return authInfo.ToClaims(), err
		}
	}

	return
}
