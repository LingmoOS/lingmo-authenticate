package charaDataManger

import (
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/log"
)

var logger = log.NewLogger("deepin-authenticate/charaDataManger")

func Start(server *dbusutil.Service) error {
	charaCommonData = newManager(server)

	charaCommonData.init()

	return nil
}
