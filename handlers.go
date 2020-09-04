package auth

import (
	"crypto/md5"
	"fmt"
	"mime"
	"net/http"
	"path"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	"github.com/ecletus/auth/claims"
	"github.com/ecletus/responder"
	"github.com/ecletus/session"
	"github.com/moisespsena-go/assetfs"
	"github.com/moisespsena/template/html/template"
)

func respond(ctx *LoginContext, claims *claims.Claims, path string) {
	if ctx.HasError() {
		if !ctx.SilentError {
			responder.With("html", func() {
				for _, err := range ctx.GetErrorsTS() {
					ctx.SessionStorer.Flash(ctx.SessionManager(), session.Message{Message: template.HTML(err), Type: "error"})
				}
				ctx.Auth.Redirector.Redirect(ctx.Writer, ctx.Request, path)
			}).With("json", func() {
				json.NewEncoder(ctx).Encode(ctx.ErrorResult())
			}).Respond(ctx.Request)
		}
	} else if !ctx.Silent {
		responder.With("html", func() {
			ctx.Auth.Redirector.Redirect(ctx.Writer, ctx.Request, path)
		}).With("json", func() {
			json.NewEncoder(ctx).Encode(map[string]interface{}{"SessionID": claims.Id, "UserID": claims.UserID})
		}).Respond(ctx.Request)
	}
}

// DefaultLoginHandler default login behaviour
var DefaultLoginHandler = func(context *LoginContext, authorize func(*LoginContext) (*claims.Claims, error)) (claims *claims.Claims, err error) {
	if claims, err = authorize(context); err == nil {
		if err = context.Auth.Signed(context.Context.Context, claims); err != nil {
			if err == ErrMaximumNumberOfAccessesReached {
				http.Error(context.Writer, err.Error(), http.StatusForbidden)
				return
			}
			http.Error(context.Writer, err.Error(), http.StatusInternalServerError)
			return
		}
		return
	}
	return
}

// DefaultRegisterHandler default register behaviour
var DefaultRegisterHandler = func(context *Context, register func(*Context) (*claims.Claims, error)) {
	claims, _ := register(context)
	respond(&LoginContext{Context: context}, claims, "auth/register")
}

// DefaultLogoutHandler default logout behaviour
var DefaultLogoutHandler = func(context *Context) {
	// Clear auth session
	context.SessionStorer.Delete(context.SessionManager())
	context.Auth.Redirector.Redirect(context.Writer, context.Request, "logout")
}

// DefaultProfileHandler default profile behaviour
var DefaultProfileHandler = func(context *Context) {
	// error handling
	responder.With("html", func() {
		context.Auth.Config.Render.Execute("auth/profile", context, context.Context)
	}).With([]string{"json"}, func() {
		// TODO write json error
	}).Respond(context.Request)
}

var cacheSince = time.Now().Format(http.TimeFormat)

// DefaultAssetHandler render auth asset file
var DefaultAssetHandler = func(context *Context) {
	pth := strings.TrimPrefix(context.Request.URL.Path, context.Auth.URLPrefix)

	if context.Request.Header.Get("If-Modified-Since") == cacheSince {
		context.Writer.WriteHeader(http.StatusNotModified)
		return
	}
	context.Writer.Header().Set("Last-Modified", cacheSince)

	if asset, err := context.Auth.Config.Render.Asset(path.Join("/auth", pth)); err == nil {
		etag := fmt.Sprintf("%x", md5.Sum(assetfs.MustData(asset)))
		if context.Request.Header.Get("If-None-Match") == etag {
			context.Writer.WriteHeader(http.StatusNotModified)
			return
		}

		if ctype := mime.TypeByExtension(filepath.Ext(pth)); ctype != "" {
			context.Writer.Header().Set("Content-Type", ctype)
		}

		context.Writer.Header().Set("Cache-control", "private, must-revalidate, max-age=300")
		context.Writer.Header().Set("ETag", etag)
		context.Writer.Write(assetfs.MustData(asset))
	} else {
		http.NotFound(context.Writer, context.Request)
	}
}
