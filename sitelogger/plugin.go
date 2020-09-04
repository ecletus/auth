package sitelogger

import (
	"net/http"

	"github.com/ecletus/core"
	"github.com/ecletus/plug"
	"github.com/moisespsena-go/xroute"
)

type Plugin struct {
	plug.PluginEventDispatcher

	SitesRegisterKey, AuthKey string
}

func (this *Plugin) RequireOptions() []string {
	return []string{this.SitesRegisterKey, this.AuthKey}
}

func (this *Plugin) Init(options *plug.Options) {
	Register := options.GetInterface(this.SitesRegisterKey).(*core.SitesRegister)
	//
	Register.OnAdd(func(site *core.Site) {
		if fmtr := site.RequestLogger("log/auth/error"); fmtr != nil {
			site.Middlewares.Add(xroute.NewMiddleware(func(next http.Handler) http.Handler {
				panic("Not implemented")
				return nil
			}))
		}
		if fmtr := site.RequestLogger("log/auth/success"); fmtr != nil {
			site.Middlewares.Add(xroute.NewMiddleware(func(next http.Handler) http.Handler {
				panic("Not implemented")
				return nil
			}))
		}
	})
}
