package github

import (
	"github.com/moisespsena/go-path-helpers"
	"github.com/moisespsena/go-i18n-modular/i18nmod"
)

var (
	PREFIX     = path_helpers.GetCalledDir()
	I18N_GROUP = i18nmod.PkgToGroup(PREFIX)
)
