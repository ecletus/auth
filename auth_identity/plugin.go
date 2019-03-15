package auth_identity

import (
	"github.com/aghape/db"
	"github.com/aghape/plug"
)

type Plugin struct {
	db.DBNames
	plug.EventDispatcher
}

func (p *Plugin) OnRegister() {
	db.Events(p).DBOnMigrate(func(e *db.DBEvent) error {
		return e.AutoMigrate(&AuthIdentity{}).Error
	})
}
