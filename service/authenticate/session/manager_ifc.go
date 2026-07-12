package session

import (
	"fmt"
	"os"

	"github.com/godbus/dbus"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

type quitMethod int

const (
	autoQuit quitMethod = iota
	manualQuit
)

type result int

const (
	pass result = iota
	fail
	unavailable
)

func (r result) toInt() int {
	return int(r)
}

func (m *Manager) Start(sender dbus.Sender, flag int, timeout int) (failNum int, busErr *dbus.Error) {
	// 查询并更新设备锁定状态
	logger.Debugf("Start with flag %d and timeout %d", flag, timeout)

	if sender != dbus.Sender(m.verifySender) {
		return 0, dbusutil.ToError(fmt.Errorf("permission denied"))
	}

	var authFlags int
	if flag == -1 {
		authFlags = AllAuthenticationFlag
	} else {
		authFlags = flag
	}
	for _, tx := range m.txs {
		if AuthTypeToFlag(tx.getType())&authFlags != 0 {
			if m.proxy.IsLimitAllowed(m.limitType, m.Username, tx.getType()) {
				tx.setLockState(lockStateUnlock)
			} else {
				tx.setLockState(lockStateLocked)
			}
		}
	}
	ret := m.controller.authenticate(flag, timeout)
	m.isStarted = true
	return ret, nil
}

// flag == -1时, 结束掉此次认证,并关闭所有资源
// flag > 0 时,结束指定认证,并关闭部分资源
func (m *Manager) End(flag int) (failNum int, busErr *dbus.Error) {
	if flag == AllAuthenticationFlag {
		m.endAll()
	} else {
		m.end(flag, newVerifyStatus(StatusCodeEnded, true, ""))
	}

	return 0, nil
}

func (m *Manager) SetQuitFlag(method int) *dbus.Error {
	v := quitMethod(method)
	if v == autoQuit || v == manualQuit {
		m.quitMethod = v
	} else {
		return dbusutil.ToError(fmt.Errorf("invalid value %d", method))
	}
	return nil
}

func (m *Manager) Quit() *dbus.Error {
	// 如果没有调用 Start，则可以直接 Quit，如果调用了 Start，则必须调用 End 才可以 Quit
	if !m.isStarted || m.controller.isEnded() {
		m.quit()
	} else {
		return dbusutil.ToError(fmt.Errorf("%v: quit failed, should end first", m.controller))
	}
	return nil
}

func (m *Manager) SetToken(sender dbus.Sender, flag int, token []byte) *dbus.Error {
	if sender != dbus.Sender(m.verifySender) {
		return dbusutil.ToError(fmt.Errorf("permission denied"))
	}

	if flag == AllAuthenticationFlag {
		flag = AllAuthenticationTypeMask
	}
	logger.Debugf("%v: set token, authTypes is %d", m.controller, flag)

	logger.Debugf("decrypt with algtype: %d, falgs: %v", m.algType, m.cryptFlags)
	var pw string
	var err error
	if m.symmetricKey == "" {
		pw, err = m.proxy.DecryptAsymmetric(m.algType, m.cryptFlags, token)
		logger.Debug("after ASymmetric.")
	} else {
		pw, err = m.proxy.DecryptSymmetric(token, []byte(m.symmetricKey))
		logger.Debug("after Symmetric")
	}
	if err != nil {
		logger.Warningf("decrypt err: %s", err.Error())
		pw = string(token)
	}

	for _, tx := range m.txs {
		if flag&AuthTypeToFlag(tx.getType()) != 0 {

			if tx.getDevState() == devStateVerifying {
				tx.setPassword(pw)
			} else {
				logger.Debugf("%v: type %s is not started", m.controller, tx.getType())
			}
		}
	}
	return nil
}

func (m *Manager) PrivilegesDisable(sender dbus.Sender) (busErr *dbus.Error) {
	senderExecPath, err := GetExecPath(m.service, string(sender))
	if err != nil {
		return dbusutil.ToError(err)
	}
	if senderExecPath != m.PrgPath {
		return dbusutil.ToError(fmt.Errorf("permission denied"))
	}

	if m.pId != 0 {
		m.proxy.UnRegisterPrivileges(m.pId)
		m.pId = 0
	}
	return nil
}

// 如果设置了该接口,那么 masterPath 可以访问该 Session 的结果,且后续 masterPath 开启的认证都为单因且只有密码认证
func (m *Manager) PrivilegesEnable(sender dbus.Sender, masterPath string) (enabled bool, busErr *dbus.Error) {
	if masterPath == "" {
		return false, dbusutil.ToError(fmt.Errorf("invaild paramter"))
	}

	_, err := os.Stat(masterPath)
	if err != nil {
		return false, dbusutil.ToError(fmt.Errorf("invaild paramter"))
	}

	senderExecPath, err := m.checkOwner(string(sender))
	if err != nil {
		return false, dbusutil.ToError(err)
	}

	if m.pId != 0 {
		return false, dbusutil.ToError(fmt.Errorf("had invoked"))
	}

	id, err := m.proxy.RegisterPrivileges(masterPath, senderExecPath)
	if err != nil {
		return false, dbusutil.ToError(err)
	}

	m.pId = id
	return true, nil
}

func (m *Manager) GetResult(sender dbus.Sender) (result int, busErr *dbus.Error) {
	ret := unavailable
	master, err := GetExecPath(m.service, string(sender))
	if err != nil {
		return ret.toInt(), dbusutil.ToError(err)
	}
	logger.Debugf("getResult: master is %s, agent is %s", master, m.PrgPath)
	if m.proxy.QueryPrivileges(master, m.PrgPath) {
		if m.statusResult == StatusCodeSuccess {
			ret = pass
		} else {
			ret = fail
		}
	}
	logger.Debugf("%v: return result is %d", m.controller, ret)
	return ret.toInt(), nil
}

func (m *Manager) EncryptKey(encryptType int, encryptMethod []int) (encType int, encMethod []int, pubKey string, busErr *dbus.Error) {
	encType, encMethod, pubKey = m.proxy.QueryEncryptKey(encryptType, encryptMethod)
	m.algType = encType
	m.cryptFlags = encMethod
	return
}

func (m *Manager) SetSymmetricKey(sender dbus.Sender, key []byte) (busErr *dbus.Error) {
	logger.Debug("SetSymmetricKey called. key:", key)
	execPath, err := GetExecPath(m.service, string(sender))
	if err != nil {
		return dbusutil.ToError(err)
	}

	if m.PrgPath != execPath {
		logger.Warningf("%s is not allowed to call the interface", execPath)
		return dbusutil.ToError(fmt.Errorf("%s is not allowed to call the interface", execPath))
	}

	if m.symmetricKey != "" {
		return dbusutil.ToError(fmt.Errorf("you have called the interface"))
	}

	symmetricKey, err := m.proxy.DecryptAsymmetric(m.algType, m.cryptFlags, key)
	if err != nil {
		logger.Warningf("decrypt err: %s", err.Error())
		return dbusutil.ToError(fmt.Errorf("decrypt err: %s", err.Error()))
	}
	m.symmetricKey = symmetricKey
	return nil
}

func (m *Manager) emitSignalStatus(authType int, status int, msg string) {
	m.signalMu.Lock()
	defer m.signalMu.Unlock()

	logger.Debugf("%v: emit signal Status authType: %s status: %d, msg: %s", m.controller, AuthFlagToType(authType), status, msg)
	err := m.service.Emit(m, "Status", authType, status, msg)
	if err != nil {
		logger.Warning(err)
	}

	if authType == AllAuthenticationFlag && status != StatusCodePrompt.toInt() {
		m.finalResultGiven = true
		if status == StatusCodeSuccess.toInt() {
			m.statusResult = StatusCodeSuccess
		} else {
			m.statusResult = StatusCodeFailure
		}
	}
}

func (m *Manager) emitStatus(authType int, status statusCode, msg string) {
	m.emitSignalStatus(authType, status.toInt(), msg)
}
