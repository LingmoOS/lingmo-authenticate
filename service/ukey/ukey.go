package ukey

import (
	"github.com/linuxdeepin/go-lib/dbusutil"
	"github.com/linuxdeepin/go-lib/log"
)

var logger = log.NewLogger("deepin-authenticate/ukey")

func Setup(service *dbusutil.Service) error {
	m := newManager(service)
	m.init()

	err := service.Export(dbusUKeyPath, m)
	if err != nil {
		return err
	}

	return nil
}
