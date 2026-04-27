package ukey

import (
	"github.com/godbus/dbus"
	ukey "github.com/linuxdeepin/go-dbus-factory/com.deepin.daemon.authenticate.ukey"
	"pkg.deepin.io/dde/authentication/service/authcommon"
)

type commonDevice struct {
	baseDevice
	core ukey.UKey
}

func (c *commonDevice) devSelect() {
	c.listenSignals()
	c.listenStatePropChanged()
}

func newCommonDevice(m *Manager, serviceName string, objPath dbus.ObjectPath, ifcName string) (*commonDevice, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	core, err := ukey.NewUKey(sysBus, serviceName, objPath)
	if err != nil {
		return nil, err
	}
	core.SetInterfaceName_(ifcName)
	d := &commonDevice{core: core}
	d.m = m
	d.setServiceName(serviceName)
	return d, nil
}

func (c *commonDevice) listenSignals() {
	c.core.InitSignalExt(c.m.sysSigLoop, true)

	_, err := c.core.ConnectVerifyResult(func(id string, msg string) {
		// 一个 uKey 设备可以对应发起多次认证,若 uKey 信号变化,则这些认证都会收到提示,需要判断 id,用来识别此次信号是否自身有用
		if c.id != "" && c.id == id {
			c.emitSignalVerifyStatus(id, msg)
		}
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (c *commonDevice) listenStatePropChanged() {
	c.core.State().ConnectChanged(func(hasValue bool, state int32) {
		if hasValue {
			for _, verifyInfo := range c.m.verificationInfoMap {
				if verifyInfo.dev.getServiceName() == c.getServiceName() {
					c.m.emitSignalState(verifyInfo.id, int(state))
				}
			}
		}
	})
}

func (c *commonDevice) setServiceName(name string) {
	c.serviceName = name
}

func (c *commonDevice) getServiceName() string {
	return c.serviceName
}

func (c *commonDevice) handleNameLost(name string) (handled bool) {
	if name == c.serviceName {
		return true
	}
	return false
}

func (c *commonDevice) devDeselect() {
	c.core.RemoveAllHandlers()
}

func (c *commonDevice) name() (string, error) {
	return c.core.Name().Get(0)
}

func (c *commonDevice) state() (int32, error) {
	return c.core.State().Get(0)
}

func (c *commonDevice) type0() (int32, error) {
	return c.core.Type().Get(0)
}

func (c *commonDevice) isClaimed() bool {
	val, err := c.core.State().Get(0)
	if err != nil {
		return false
	}

	return authcommon.UKeyState(val) == authcommon.UKeyStateDeviceVerifying
}

func (c *commonDevice) capability() (int32, error) {
	return c.core.Capability().Get(0)
}

func (c *commonDevice) verify(username, id string) error {
	return c.core.Verify(0, username, id)
}

func (c *commonDevice) stopVerify(username, id string) error {
	return c.core.StopVerify(0, username, id)
}

func (c *commonDevice) setPin(username, id string, pin string) error {
	return c.core.SetPin(0, username, id, pin)
}

func (c *commonDevice) setSessionPath(username, id string, path string) error {
	return c.core.SetSessionPath(0, username, id, path)
}

func (c *commonDevice) getPINLength(username string) (int32, error) {
	return c.core.GetPINLength(0, username)
}

func (c *commonDevice) getUserList() ([]string, error) {
	return c.core.GetUserList(0)
}
