package charaDataManger

import (
	"github.com/godbus/dbus"
	biometrics "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.authenticate.BiometricsDriver"
	ofdbus "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.dbus"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
)

// 录入过程中的状态码
type EnrollStatusCode int32

type CommonDriver struct {
	// 统一生物识别接口
	Core            biometrics.BiometricsDriver
	proxy           proxyDataManger
	sysBus          *dbus.Conn
	Configer        InterfaceConfig
	signalLoop      *dbusutil.SignalLoop
	DriverCharaType CharaType
	UniqueName      dbus.Sender
}

type proxyDataManger interface {
	handleDriverSignalEnrollStatus(actionId ActionId, code int32, msg string)
	handleDriverSignalVerifyStatus(actionId ActionId, code int32, msg string)
	handleDriverListChange(serverName string, chara []Chara)
	HandleDriverCharaTypeChange(serverName string, oldcharaType CharaType, newcharaType CharaType)
}

func newCommonDriver(serviceName string, objPath dbus.ObjectPath, ifcName string, proxy proxyDataManger) (*CommonDriver, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	core, err := biometrics.NewBiometricsDriver(sysBus, serviceName, objPath)
	if err != nil {
		return nil, err
	}
	core.SetInterfaceName_(ifcName)

	cd := &CommonDriver{
		Core:       core,
		proxy:      proxy,
		sysBus:     sysBus,
		signalLoop: dbusutil.NewSignalLoop(sysBus, 10),
	}
	charaType, err := cd.Core.CharaType().Get(0)

	if err != nil {
		logger.Warning(err)
		return nil, err
	}

	cd.DriverCharaType = CharaType(charaType)

	dbusDaemon := ofdbus.NewDBus(sysBus)
	unionName, err := dbusDaemon.GetNameOwner(0, serviceName)
	if err != nil {
		logger.Warning(err)
	}
	cd.UniqueName = dbus.Sender(unionName)
	return cd, nil
}

func (cd *CommonDriver) init() error {

	cd.Core.InitSignalExt(cd.signalLoop, true)
	cd.signalLoop.Start()

	// 监听特征值变化
	err := cd.Core.List().ConnectChanged(func(hasValue bool, charaList []string) {
		if hasValue {
			var chara []Chara
			for _, val := range charaList {
				chara = append(chara, Chara(val))
			}
			cd.proxy.handleDriverListChange(cd.Core.ServiceName_(), chara)
		}
	})
	if err != nil {
		logger.Warning(err)
	}
	// 监听特征类型变化
	err = cd.Core.CharaType().ConnectChanged(func(hasValue bool, value int32) {
		if hasValue {
			if cd.DriverCharaType != CharaType(value) {
				oldCharaType := cd.DriverCharaType
				cd.DriverCharaType = CharaType(value)
				cd.proxy.HandleDriverCharaTypeChange(cd.Core.ServiceName_(), oldCharaType, cd.DriverCharaType)
			}
		}
	})
	if err != nil {
		logger.Warning(err)
	}
	_, err = cd.Core.ConnectEnrollStatus(func(action string, enrollStatusCode int32, msg string) {
		logger.Debugf("ConnectEnrollStatus action id %s,eroll status %d and msg %s", action, enrollStatusCode, msg)
		cd.proxy.handleDriverSignalEnrollStatus(ActionId(action), enrollStatusCode, msg)
	})
	if err != nil {
		logger.Warning(err)
	}

	_, err = cd.Core.ConnectVerifyStatus(func(action string, verifyStatusCode int32, msg string) {
		logger.Debugf("ConnectVerifyStatus action id %s,verify status %d and msg %s", action, verifyStatusCode, msg)
		cd.proxy.handleDriverSignalVerifyStatus(ActionId(action), verifyStatusCode, msg)
	})
	if err != nil {
		logger.Warning(err)
	}

	return err
}
