package authenticate

import (
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/log"
)

var logger = log.NewLogger("deepin-authenticate/authenticate")

func Setup(service *dbusutil.Service) error {
	m, _ := newManage(service)

	m.init()
	err := service.Export(dbusServicePath, m)
	if err != nil {
		return err
	}

	return nil
}
