package fingerprint

import (
	"github.com/godbus/dbus"
	aufp "github.com/linuxdeepin/go-dbus-factory/com.deepin.daemon.authenticate.fingerprint"
)

type commonDevice struct {
	baseDevice
	core aufp.CommonDevice
}

func newCommonDevice(m *Manager, serviceName string, objPath dbus.ObjectPath, ifcName string) (*commonDevice, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	core, err := aufp.NewCommonDevice(sysBus, serviceName, objPath)
	if err != nil {
		return nil, err
	}
	core.SetInterfaceName_(ifcName)
	d := &commonDevice{core: core}
	d.m = m
	d.claimFn = d.doClaim
	return d, nil
}

func (d *commonDevice) select0() {
	d.listenSignals()
}

func (d *commonDevice) deselect() {
	d.core.RemoveAllHandlers()
}

func (d *commonDevice) listenSignals() {
	d.core.InitSignalExt(d.m.sysSigLoop, true)
	_, err := d.core.ConnectEnrollStatus(func(userUuid string, code int32, msg string) {
		if userUuid == d.user.uuid {
			d.emitSignalEnrollStatusRaw(int(code), msg)
		}
	})
	if err != nil {
		logger.Warning(err)
	}

	_, err = d.core.ConnectVerifyStatus(func(userUuid string, code int32, msg string) {
		if userUuid == d.user.uuid {
			d.emitSignalVerifyStatusRaw(int(code), msg)
		}
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (d *commonDevice) available() (bool, error) {
	state, err := d.core.State().Get(0)
	if err != nil {
		return false, err
	}
	return state&DeviceStateNormal != 0, nil
}

func (d *commonDevice) name() (string, error) {
	return d.core.Name().Get(0)
}

func (d *commonDevice) capability() (int32, error) {
	return d.core.Capability().Get(0)
}

func (d *commonDevice) doClaim(userInfo UserInfo, claimed bool) error {
	err := d.core.Claim(0, userInfo.uuid, claimed)
	return err
}

func (d *commonDevice) enroll(finger string) error {
	err := d.core.Enroll(0, d.user.uuid, finger)
	return err
}

func (d *commonDevice) stopEnroll() error {
	err := d.core.StopEnroll(0)
	return err
}

func (d *commonDevice) verify(finger string) error {
	err := d.core.Verify(0, finger)
	return err
}

func (d *commonDevice) stopVerify() error {
	err := d.core.StopVerify(0)
	return err
}

func (d *commonDevice) deleteFinger(userInfo UserInfo, finger string) error {
	err := d.core.DeleteFinger(0, userInfo.uuid, finger)
	return err
}

func (d *commonDevice) deleteAllFingers(userInfo UserInfo) error {
	err := d.core.DeleteAllFingers(0, userInfo.uuid)
	return err
}

func (d *commonDevice) listFingers(userInfo UserInfo) ([]string, error) {
	fingers, err := d.core.ListFingers(0, userInfo.uuid)
	return fingers, err
}

func (d *commonDevice) renameFinger(userInfo UserInfo, finger, newName string) error {
	err := d.core.RenameFinger(0, userInfo.uuid, finger, newName)
	return err
}
