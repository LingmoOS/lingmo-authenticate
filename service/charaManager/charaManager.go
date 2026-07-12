package charaManager

import (
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/log"
)

var loggerCharaManger = log.NewLogger("deepin-authenticate/charaManager")

func Setup(service *dbusutil.Service) error {
	m := newManager(service)
	m.init()

	err := service.Export(dBusCharaMangerPath, m)
	if err != nil {
		return err
	}

	return nil
}
