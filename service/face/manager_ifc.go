package face

import (
	"fmt"
	"time"

	"github.com/linuxdeepin/dde-api/polkit"

	"github.com/godbus/dbus"
	ac "pkg.deepin.io/dde/authentication/service/authcommon"
	"pkg.deepin.io/dde/authentication/service/task"
	"github.com/linuxdeepin/go-lib/dbusutil"
)

const (
	actionIdFaceEnroll = "com.deepin.daemon.authenticate.Face.enroll"
	actionIdFaceRename = "com.deepin.daemon.authenticate.Face.rename-enrolled-face"
	actionIdFaceDelete = "com.deepin.daemon.authenticate.Face.delete-enrolled-face"
)

func (m *Manager) StartEnroll(sender dbus.Sender, username, serviceName, faceName string) (id string, busErr *dbus.Error) {
	err := polkit.CheckAuth(actionIdFaceEnroll, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return "", dbusutil.ToError(err)
	}

	if m.isDeviceClaimed(serviceName) {
		return "", dbusutil.ToError(fmt.Errorf("device is claimed"))
	}

	caller, err := m.genCallerInfo(sender, username, serviceName)
	if err != nil {
		return "", dbusutil.ToError(err)
	}

	caller.dev.devSelect()

	err = caller.dev.claim(true)
	if err != nil {
		return caller.id, dbusutil.ToError(err)
	}

	// listen signal NameLost, if owner changed, call function proactive
	task.GetTaskManager().AddSignalTask("NameLost", caller.id, func(id string, paras ...interface{}) bool {
		concerned, needDel, caller := m.isConcernedSignalNameLost(id, paras...)
		if concerned {
			logger.Debugf("do action when NameLost for id = %s", caller.id)
			m.emitSignalEnrollStatus(caller.id, username, int32(ac.FaceEnrollException), "service quited")
		}
		return needDel
	}, false)

	caller.dev.setInvokeId(caller.id)

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return caller.dev.startEnroll(paras[0].(string), paras[1].(string))
	}, caller.uuid, faceName)
	if err != nil {
		return caller.id, dbusutil.ToError(err)
	}

	sockPath, key, size, err := caller.dev.getShareMemInfo()
	if err != nil {
		return "", dbusutil.ToError(err)
	}

	caller.shmSockPath = sockPath
	caller.shmKey = key
	caller.shmSize = size

	return caller.id, nil
}

func (m *Manager) StopEnroll(sender dbus.Sender, id string) (busErr *dbus.Error) {
	caller, err := m.getCallerInfo(id)
	if err != nil {
		return dbusutil.ToError(err)
	}

	if caller.sender != sender {
		logger.Warningf("caller %s permission denied", sender)
		return dbusutil.ToError(fmt.Errorf("caller %s permission denied", sender))
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return caller.dev.stopEnroll()
	})
	if err != nil {
		logger.Warning(err)
	}

	caller.dev.devDeSelect()
	m.deleteCallerInfo(caller.id)

	task.GetTaskManager().DelSignalTask("NameLost", caller.id)

	err = caller.dev.claim(false)
	if err != nil {
		return dbusutil.ToError(err)
	}

	return nil
}

func (m *Manager) StartVerify(sender dbus.Sender, username, serviceName string, timeout int) (id string, busErr *dbus.Error) {
	if m.isDeviceClaimed(serviceName) {
		return "", dbusutil.ToError(fmt.Errorf("device is claimed"))
	}

	caller, err := m.genCallerInfo(sender, username, serviceName)
	if err != nil {
		return "", dbusutil.ToError(err)
	}

	caller.dev.devSelect()

	err = caller.dev.claim(true)
	if err != nil {
		return caller.id, dbusutil.ToError(err)
	}

	task.GetTaskManager().AddSignalTask("NameLost", caller.id, func(id string, paras ...interface{}) bool {
		concerned, needDel, caller := m.isConcernedSignalNameLost(id, paras...)
		if concerned {
			logger.Debugf("do action when NameLost for id = %s", caller.id)
			m.emitSignalVerifyStatus(caller.id, username, int32(ac.FaceVerifyException), "service quited")
		}
		return needDel
	}, false)

	caller.dev.setInvokeId(caller.id)

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return caller.dev.startVerify(paras[0].(string), paras[1].(int))
	}, caller.uuid, timeout)
	if err != nil {
		return caller.id, dbusutil.ToError(err)
	}

	return caller.id, nil
}

func (m *Manager) StopVerify(sender dbus.Sender, id string) (busErr *dbus.Error) {
	caller, err := m.getCallerInfo(id)
	if err != nil {
		return dbusutil.ToError(err)
	}

	if caller.sender != sender {
		logger.Warningf("caller %s permission denied", sender)
		return dbusutil.ToError(fmt.Errorf("caller %s permission denied", sender))
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return caller.dev.stopVerify()
	})
	if err != nil {
		logger.Warning(err)
	}

	caller.dev.devDeSelect()
	m.deleteCallerInfo(caller.id)

	task.GetTaskManager().DelSignalTask("NameLost", caller.id)

	err = caller.dev.claim(false)
	if err != nil {
		return dbusutil.ToError(err)
	}

	return nil
}

func (m *Manager) ListFaces(serviceName, username string) (faces []string, busErr *dbus.Error) {
	dev, err := m.newDevice(serviceName)
	if err != nil {
		return nil, dbusutil.ToError(err)
	}

	userInfo, err := ac.GetUserInfo(username)
	if err != nil {
		logger.Warningf("get user %s err: %s", username, err)
		return nil, dbusutil.ToError(err)
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		faces, err = dev.listFaces(paras[0].(string))
		return err
	}, userInfo.Uuid)
	if err != nil {
		return nil, dbusutil.ToError(err)
	}

	return faces, nil
}

func (m *Manager) RenameFace(sender dbus.Sender, serviceName, username, oldFace, newFace string) (busErr *dbus.Error) {
	err := polkit.CheckAuth(actionIdFaceRename, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev, err := m.newDevice(serviceName)
	if err != nil {
		return dbusutil.ToError(err)
	}

	userInfo, err := ac.GetUserInfo(username)
	if err != nil {
		logger.Warningf("get user %s err: %s", username, err)
		return dbusutil.ToError(err)
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return dev.renameFace(paras[0].(string), paras[1].(string), paras[2].(string))
	}, userInfo.Uuid, oldFace, newFace)
	if err != nil {
		return dbusutil.ToError(err)
	}

	return nil
}

func (m *Manager) DeleteFace(sender dbus.Sender, serviceName, username, faceName string) (busErr *dbus.Error) {
	err := polkit.CheckAuth(actionIdFaceDelete, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev, err := m.newDevice(serviceName)
	if err != nil {
		return dbusutil.ToError(err)
	}

	userInfo, err := ac.GetUserInfo(username)
	if err != nil {
		logger.Warningf("get user %s err: %s", username, err)
		return dbusutil.ToError(err)
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return dev.deleteFace(paras[0].(string), paras[1].(string))
	}, userInfo.Uuid, faceName)
	if err != nil {
		return dbusutil.ToError(err)
	}
	return nil
}

func (m *Manager) DeleteFaces(sender dbus.Sender, serviceName, username string) (busErr *dbus.Error) {
	err := polkit.CheckAuth(actionIdFaceDelete, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev, err := m.newDevice(serviceName)
	if err != nil {
		return dbusutil.ToError(err)
	}

	userInfo, err := ac.GetUserInfo(username)
	if err != nil {
		logger.Debugf("get user %s err: %s", username, err)
		return dbusutil.ToError(err)
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return dev.deleteFaces(paras[0].(string))
	}, userInfo.Uuid)
	if err != nil {
		return dbusutil.ToError(err)
	}
	return nil
}

func (m *Manager) SetDefaultDevice(serviceName, device string) (busErr *dbus.Error) {
	dev, err := m.newDevice(serviceName)
	if err != nil {
		return dbusutil.ToError(err)
	}

	err = ac.SyncCallWithTimeout(time.Second*3, func(paras ...interface{}) error {
		return dev.setDefaultDevice(paras[0].(string))
	}, device)
	if err != nil {
		return dbusutil.ToError(err)
	}

	m.defaultMapRwMu.Lock()
	defer m.defaultMapRwMu.Unlock()

	m.defaultMap[serviceName] = device

	return nil
}

func (m *Manager) SetDefaultService(serviceName string) (busErr *dbus.Error) {
	m.deviceMapRwMu.RLock()
	defer m.deviceMapRwMu.RUnlock()

	if _, ok := m.deviceMap[serviceName]; !ok {
		logger.Debugf("service %s not exist", serviceName)
		return dbusutil.ToError(fmt.Errorf("service %s not exist", serviceName))
	}

	m.setPropDefaultService(serviceName)

	m.defaultMapRwMu.RLock()
	m.setPropDefaultDevice(m.defaultMap[serviceName])
	m.defaultMapRwMu.RUnlock()

	err := writeToFile(defaultConfigFile, serviceName)
	if err != nil {
		logger.Warning(err)
	}

	return dbusutil.ToError(err)
}

func (m *Manager) GetShareMemInfo(id string) (sockPath string, key string, size int32, busErr *dbus.Error) {
	caller, err := m.getCallerInfo(id)
	if err != nil {
		return "", "", 0, dbusutil.ToError(err)
	}

	return caller.shmSockPath, caller.shmKey, caller.shmSize, nil
}
