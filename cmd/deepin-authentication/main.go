package main

import (
	"os"

	"github.com/linuxdeepin/go-lib/dbusutil"
	"github.com/linuxdeepin/go-lib/gettext"
	"github.com/linuxdeepin/go-lib/log"

	"pkg.deepin.io/dde/authentication/service/authenticate"
	"pkg.deepin.io/dde/authentication/service/charaDataManger"
	"pkg.deepin.io/dde/authentication/service/charaManager"
	"pkg.deepin.io/dde/authentication/service/face"
	"pkg.deepin.io/dde/authentication/service/fingerprint"
	"pkg.deepin.io/dde/authentication/service/multifactor"
	"pkg.deepin.io/dde/authentication/service/ukey"
)

const (
	dbusServiceName = "com.deepin.daemon.Authenticate"
)

var logger = log.NewLogger("daemon/deepin-authenticate")

func main() {
	// 设置为英文环境
	os.Setenv("LANG", "en_US.UTF-8")
	os.Setenv("LANGUAGE", "en_US")

	gettext.InitI18n()
	gettext.Textdomain("deepin-authentication")

	service, err := dbusutil.NewSystemService()
	if err != nil {
		logger.Fatal("failed to call NewSystemService. error:", err)
	}

	hasOwner, err := service.NameHasOwner(dbusServiceName)
	if err != nil {
		logger.Fatal("failed to call NameHasOwner. error:", err)
	}

	if hasOwner {
		logger.Fatalf("name %q already has the owner", dbusServiceName)
	}

	multifactor.Init()

	err = charaDataManger.Start(service)
	if err != nil {
		logger.Warning("failed to setup charaDataManger Service. error:", err)
	}
	err = authenticate.Setup(service)
	if err != nil {
		logger.Warning("failed to setup Authenticate Service. error:", err)
	}

	err = fingerprint.Setup(service)
	if err != nil {
		logger.Warning("failed to setup fingerprint Service. error:", err)
	}

	err = ukey.Setup(service)
	if err != nil {
		logger.Warning("failed to setup uKey Service. error:", err)
	}

	err = face.Setup(service)
	if err != nil {
		logger.Warning("failed to setup face Service. error:", err)
	}

	err = charaManager.Setup(service)
	if err != nil {
		logger.Warning("failed to setup charaManager Service. error:", err)
	}
	err = service.RequestName(dbusServiceName)
	if err != nil {
		logger.Fatal("failed to call RequestName, name:", dbusServiceName, "err: ", err)
	}

	service.Wait()
}
