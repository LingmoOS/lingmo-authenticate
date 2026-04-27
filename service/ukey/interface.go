package ukey

import (
	"fmt"

	"github.com/godbus/dbus"
	"github.com/linuxdeepin/go-lib/dbusutil"

	"pkg.deepin.io/dde/authentication/service/authcommon"
	"pkg.deepin.io/dde/authentication/service/task"
)

func (m *Manager) StartVerify(id string) *dbus.Error {
	info, err := m.getVerificationInfo(id)
	if err != nil {
		return dbusutil.ToError(err)
	}

	state, err := info.dev.state()
	if err != nil {
		return dbusutil.ToError(err)
	}

	m.emitSignalState(id, int(state))

	err = info.dev.verify(info.uuid, id)
	if err != nil {
		return dbusutil.ToError(err)
	}

	return nil
}

func (m *Manager) SetPin(id string, pin string) *dbus.Error {
	info, err := m.getVerificationInfo(id)
	if err != nil {
		return dbusutil.ToError(err)
	}

	err = info.dev.setPin(info.uuid, id, pin)
	if err != nil {
		return dbusutil.ToError(err)
	}
	return nil
}

func (m *Manager) StopVerify(id string) *dbus.Error {
	defer func() {
		m.deleteVerificationInfo(id)
		m.deleteMarkedService([]string{id})
	}()

	info, err := m.getVerificationInfo(id)
	if err != nil {
		return dbusutil.ToError(err)
	}
	info.dev.devDeselect()

	err = info.dev.stopVerify(info.uuid, id)
	if err != nil {
		return dbusutil.ToError(err)
	}
	return nil
}

func (m *Manager) SetSessionPath(id string) *dbus.Error {
	info, err := m.getVerificationInfo(id)
	if err != nil {
		return dbusutil.ToError(err)
	}
	type0, err := info.dev.type0()
	if err != nil {
		return dbusutil.ToError(err)
	}
	//如果不支持,则不设置
	if uKeyType(type0) != typeDongle {
		return nil
	}
	if info.sessionPath == "" {
		dev := info.dev
		user := info.username
		fn := func(id string, paras ...interface{}) bool {
			if len(paras) != 2 {
				return false
			}

			var sessionPath dbus.ObjectPath
			var ok bool
			if sessionPath, ok = paras[1].(dbus.ObjectPath); !ok {
				return false
			}

			if !authcommon.IsGUISession(sessionPath) {
				return false
			}

			username := authcommon.GetUsernameBySessionPath(sessionPath)
			if username == "" {
				return false
			}

			if user != username {
				return false
			}

			userInfo, err := authcommon.GetUserInfo(user)
			if err != nil {
				logger.Warning(err)
				return false
			}

			err = dev.setSessionPath(userInfo.Uuid, id, userInfo.SessionPath)
			if err != nil {
				logger.Warning(err)
			}
			return true
		}
		task.GetTaskManager().AddSignalTask("SessionNew", user, fn, false)
		return nil
	}

	err = info.dev.setSessionPath(info.uuid, id, info.sessionPath)
	if err != nil {
		return dbusutil.ToError(err)
	}
	return nil
}

func (m *Manager) ConstructVerification(serviceName, username string, useDefaultService bool) (id string, busErr *dbus.Error) {
	// 对于每次认证,都创建一个指向 uKey 设备的 dbus 对象
	dev, err := m.newDevice(serviceName, useDefaultService)

	if err != nil {
		return "", dbusutil.ToError(err)
	}

	userInfo, err := authcommon.GetUserInfo(username)
	if err != nil {
		return "", dbusutil.ToError(err)
	}

	capability, _ := dev.capability()
	// 如果设备不支持同时开启多个认证，并且此设备已经被占用，则需要关闭此设备的认证
	if uKeyCapability(capability) != capabilityMulti && dev.isClaimed() {
		infoArray := m.selectVerificationInfos(func(v *verificationInfo) bool {
			if v.serviceName == serviceName {
				return true
			}
			return false
		})

		for _, info := range infoArray {
			logger.Debugf("%s not support multi verify, stop last verify", info.id)
			msg, err := m.genUKeyVerifyMsg(info.uuid, authcommon.UKeyVerifyFailed, "verification terminated by next")
			if err != nil {
				logger.Warning(err)
			}
			m.emitSignalVerifyResult(info.id, msg)
		}
	}

	dev.devSelect()
	id = m.genId()
	// 设置 id 作为唯一标识
	dev.setVerifyId(id)

	m.verificationInfoMapMux.Lock()
	m.verificationInfoMap[id] = &verificationInfo{
		id:                id,
		serviceName:       serviceName,
		useDefaultService: useDefaultService,
		username:          username,
		uuid:              userInfo.Uuid,
		sessionPath:       userInfo.SessionPath,
		dev:               dev,
	}
	m.verificationInfoMapMux.Unlock()
	return id, nil
}

func (m *Manager) SetDefaultDevice(device string) *dbus.Error {
	if _, ok := m.uKeyServiceMap[device]; ok {
		m.setPropDefaultDevice(device)
		err := writeToFile(defaultConfigFile, device)
		if err != nil {
			return dbusutil.ToError(err)
		}
		return nil
	}
	return dbusutil.ToError(fmt.Errorf("not found device %s", device))
}

func (m *Manager) GetPINLength(serviceName, username string, useDefaultDevice bool) (length int, busErr *dbus.Error) {
	dev, err := m.newDevice(serviceName, useDefaultDevice)
	if err != nil {
		return 0, dbusutil.ToError(err)
	}

	userInfo, err := authcommon.GetUserInfo(username)
	if err != nil {
		return 0, dbusutil.ToError(err)
	}

	pinLength, err := dev.getPINLength(userInfo.Uuid)
	return int(pinLength), dbusutil.ToError(err)
}

func (m *Manager) GetUserList(serviceName string, useDefaultDevice bool) (users []string, busErr *dbus.Error) {
	dev, err := m.newDevice(serviceName, useDefaultDevice)
	if err != nil {
		return nil, dbusutil.ToError(err)
	}

	users, err = dev.getUserList()
	return users, dbusutil.ToError(err)
}
