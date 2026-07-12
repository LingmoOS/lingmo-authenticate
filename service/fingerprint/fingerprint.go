package fingerprint

import (
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/log"
)

var logger = log.NewLogger("deepin-authenticate/fingerprint")

func Setup(service *dbusutil.Service) error {
	m, _ := newManager(service)
	m.init()

	err := service.Export(dbusFingerPrintPath, m)
	if err != nil {
		return err
	}

	return nil
}
