package session

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/LingmoOS/golang-github-lingmo-go-lib/strv"

	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"

	"github.com/godbus/dbus"

	authenticate "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.authenticate"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	mf "pkg.deepin.io/dde/authentication/service/multifactor"
	"pkg.deepin.io/dde/authentication/service/ukey"
)

type UKeyTx struct {
	baseTx
	uKeyObj        authenticate.UKey
	verificationId string
	signalLoop     *dbusutil.SignalLoop
	conf           *mf.Config
	deviceLost     bool
	hasInit        bool
	listened       bool
	endMux         sync.Mutex
	isMFA          bool
}

func stateToStatusCode(s UKeyState, lost bool) statusCode {
	if s == UKeyStateDeviceException {
		return StatusCodeError
	} else if s == UKeyStateDeviceOk {
		if lost {
			return StatusCodeRecover
		} else {
			return StatusCodePrompt
		}
	} else if s == UKeyStateDeviceVerifying {
		return StatusCodeVerify
	} else if s == UKeyStateDeviceNotExist {
		return StatusCodeException
	} else {
		return StatusCodeUnknown
	}
}

func newUKeyTx(isMFA bool) *UKeyTx {
	sysBus, err := dbus.SystemBus()

	if err != nil {
		logger.Warning(err)
		return nil
	}

	tx := &UKeyTx{}
	tx.type0 = AuthTypeUKey
	tx.isMFA = isMFA
	tx.uKeyObj = authenticate.NewUKey(sysBus)
	tx.signalLoop = dbusutil.NewSignalLoop(sysBus, 10)
	return tx
}

func getUKeyDevicesInfo() []ukey.ValidDeviceInfo {
	bus, err := dbus.SystemBus()
	if err != nil {
		logger.Warning(err)
		return nil
	}

	uKey := authenticate.NewUKey(bus)
	devices, err := uKey.ValidDevices().Get(0)
	if err != nil {
		logger.Warning("get valid devices err:", err)
		return nil
	}

	var devicesInfo []ukey.ValidDeviceInfo
	err = json.Unmarshal([]byte(devices), &devicesInfo)
	if err != nil {
		logger.Warning(err)
		return nil
	}
	return devicesInfo
}

func hasValidUKeyDevices() []string {
	devicesInfo := getUKeyDevicesInfo()
	if devicesInfo == nil {
		return nil
	}

	var validDevices []string
	for _, dev := range devicesInfo {
		validDevices = append(validDevices, dev.ServiceName)
	}
	return validDevices
}

func isUKeySupportedUser(username string, serviceName string, useDefaultDevice bool) bool {
	bus, err := dbus.SystemBus()
	if err != nil {
		logger.Warning(err)
		return false
	}

	userInfo, err := GetUserInfo(username)
	if err != nil {
		logger.Warning("GetUserInfo err:", err)
		return false
	}

	uKey := authenticate.NewUKey(bus)
	users, err := uKey.GetUserList(0, serviceName, useDefaultDevice)
	if err != nil {
		logger.Warning("GetUserList err:", err)
		return false
	}

	if strv.Strv(users).Contains(userInfo.Uuid) {
		return true
	}

	return false
}

func getPINLength(serviceName, username string, useDefaultDevice bool) int {
	bus, err := dbus.SystemBus()
	if err != nil {
		logger.Warning(err)
		return 0
	}

	uKey := authenticate.NewUKey(bus)
	value, err := uKey.GetPINLength(0, serviceName, username, useDefaultDevice)
	if err != nil {
		logger.Warning("GetPINLength err:", err)
		return 0
	}
	return int(value)
}

func (u *UKeyTx) listenSignal() {
	logger.Debug("start listenSignal for", u.getType())
	u.signalLoop.Start()
	u.uKeyObj.InitSignalExt(u.signalLoop, true)

	_, err := u.uKeyObj.ConnectVerifyResult(func(id, msg string) {
		var result UKeyResult
		var authStatus *verifyStatus
		err := json.Unmarshal([]byte(msg), &result)
		if err != nil {
			logger.Warning(err)
			return
		}
		if id == u.verificationId {
			if result.Result == UKeyVerifySuccess {
				authStatus = newVerifyStatus(StatusCodeSuccess, true, "")
				err = u.uKeyObj.SetSessionPath(0, u.verificationId)
				if err != nil {
					logger.Warning(err)
				}
			} else {
				authStatus = newVerifyStatus(StatusCodeFailure, true, "")
			}
			u.giveStatus(u, authStatus)
		}

	})
	if err != nil {
		logger.Warning(err)
	}
	// 监听 uKey 设备状态,在拔出的时候发出提示信息,但不结束此次认证,在插入的时候更新提示,恢复 uKey 认证
	_, err = u.uKeyObj.ConnectState(func(id string, state int32) {
		logger.Debugf("receive State signal for id: %s, state: %d", id, state)
		if u.verificationId == id {
			u.giveStatus(u, newVerifyStatus(stateToStatusCode(UKeyState(state), u.deviceLost), false, UKeyState(state).String()))
			if UKeyState(state) == UKeyStateDeviceException || UKeyState(state) == UKeyStateDeviceNotExist {
				u.end(closeVerify)
				if UKeyState(state) == UKeyStateDeviceNotExist {
					u.deviceLost = true
				}
			} else if UKeyState(state) == UKeyStateDeviceOk && u.deviceLost {
				// device reconnect
				u.deviceLost = false
				u.hasInit = false
			}
		}
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (u *UKeyTx) authenticate() error {
	var err error
	if !u.hasInit {
		u.hasInit = true
		username := u.username()

		var conf *mf.Config
		// 如果是 MFA ,则寻找 MFA 配置
		if u.isMFA {
			conf = mf.MfConfig.GetConfig(u.appType)
			if conf == nil {
				err = fmt.Errorf("can not get %d's config", u.appType)
				return err
			}
		} else {
			// 如果是 SFA ,则使用默认的配置
			conf = &mf.Config{ApplicationType: mf.AppTypeIntToAppTypeString(u.appType), RequestVerificationType: []*mf.AuthTypeConfig{{Type: mf.AuthTypeToMfaType(u.type0), Service: "*"}}}
		}

		uKeyConfig := conf.GetAuthTypeConfig(u.type0)
		if uKeyConfig == nil {
			return fmt.Errorf("can not get %d's uKey's config", u.appType)
		}

		id, err := u.uKeyObj.ConstructVerification(0, uKeyConfig.Service, username, uKeyConfig.IsUseDefaultService())
		if err != nil {
			logger.Warning(err)
			return err
		}
		u.verificationId = id
		u.conf = conf

		if !u.listened {
			u.listenSignal()
			u.listened = true
		}
	}

	if err != nil {
		u.giveStatus(u, newVerifyStatus(StatusCodeError, false, err.Error()))
		return err
	}

	u.giveStatus(u, defaultVerifyStatusStarted)
	go func() {
		logger.Debug("start verify for", u.getType())
		err = u.uKeyObj.StartVerify(0, u.verificationId)
		if err != nil {
			logger.Warning(err)
			u.uKeyObj.StopVerify(0, u.verificationId)
			u.giveStatus(u, newVerifyStatus(StatusCodeError, false, err.Error()))
			return
		}
	}()

	return nil
}

func (u *UKeyTx) setPassword(pin string) {
	go func() {
		err := u.uKeyObj.SetPin(0, u.verificationId, pin)
		if err != nil {
			logger.Warning(err)
			u.giveStatus(u, newVerifyStatus(StatusCodeError, false, err.Error()))
		}
	}()
}

func (u *UKeyTx) end(ct closeType) {
	u.endMux.Lock()
	defer u.endMux.Unlock()

	logger.Debugf("%v end, close type: %s", u, ct)
	u.giveStatus(u, defaultVerifyStatusEnd)

	if ct == closeAllResource {
		go func() {
			err := u.uKeyObj.StopVerify(0, u.verificationId)
			if err != nil {
				logger.Warning(err)
			}
		}()
		if u.listened {
			logger.Debug("remove all handler for", u.type0)
			u.uKeyObj.RemoveAllHandlers()
			u.signalLoop.Stop()
		}
	}
}

func (u *UKeyTx) getVerifyTip() string {
	return Tr("PIN")
}

func (u *UKeyTx) shouldIgnore(status statusCode) bool {
	if status == StatusCodeVerify || status == StatusCodePrompt || status == StatusCodeLocked || status == StatusCodeEnded || status == StatusCodeStarted {
		return true
	}
	return false
}

func (u *UKeyTx) setLockState(s lockState) {
	if u.getLockState() != s {
		u.giveStatus(u, newVerifyStatus(s.toStatusCode(), true, ""))
		if s == lockStateLocked {
			if u.devState == devStateVerifying {
				u.end(closeVerify)
			}
		}
	}
	u.lockState = s
}
