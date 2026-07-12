package face

import (
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/log"
)

var logger = log.NewLogger("deepin-authenticate/face")

func Setup(service *dbusutil.Service) error {
	m := newManager(service)
	m.init()

	err := service.Export(dBusFacePath, m)
	if err != nil {
		return err
	}

	return nil
}
