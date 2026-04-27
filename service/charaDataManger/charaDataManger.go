package charaDataManger

import (
	"github.com/linuxdeepin/go-lib/dbusutil"
	"github.com/linuxdeepin/go-lib/log"
)

var logger = log.NewLogger("deepin-authenticate/charaDataManger")

func Start(server *dbusutil.Service) error {
	charaCommonData = newManager(server)

	charaCommonData.init()

	return nil
}
