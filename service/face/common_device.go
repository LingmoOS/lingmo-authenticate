package face

import (
	"errors"

	"github.com/godbus/dbus"
	face "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.authenticate.face"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
)

type commonDevice struct {
	core        face.Face
	proxy       parentInteractiveBridge
	sysBus      *dbus.Conn
	invokeId    string
	service     string
	handlerInit bool
	selected    bool
	sigLoop     *dbusutil.SignalLoop
}

type parentInteractiveBridge interface {
	emitDeviceSignalEnrollStatus(string, string, int32, string)
	emitDeviceSignalVerifyStatus(string, string, int32, string)
	emitDeviceSignalStatus(string, int32)

	getSigLoop() *dbusutil.SignalLoop
}

func newCommonDevice(serviceName string, objPath dbus.ObjectPath, ifcName string, proxy parentInteractiveBridge) (*commonDevice, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	core, err := face.NewFace(sysBus, serviceName, objPath)
	if err != nil {
		return nil, err
	}
	core.SetInterfaceName_(ifcName)

	cd := &commonDevice{core: core, proxy: proxy, sysBus: sysBus, service: serviceName}

	if proxy == nil || proxy.getSigLoop() == nil {
		return nil, errors.New("para is invalid")
	}
	cd.sigLoop = proxy.getSigLoop()

	return cd, nil
}

func (cd *commonDevice) setInvokeId(id string) {
	cd.invokeId = id
}

func (cd *commonDevice) devSelect() {
	cd.core.InitSignalExt(cd.sigLoop, true)

	_, err := cd.core.ConnectEnrollStatus(func(uuid string, code int32, desc string) {
		cd.proxy.emitDeviceSignalEnrollStatus(cd.invokeId, uuid, code, desc)
	})
	if err != nil {
		logger.Warning(err)
	}

	_, err = cd.core.ConnectVerifyStatus(func(uuid string, code int32, desc string) {
		cd.proxy.emitDeviceSignalVerifyStatus(cd.invokeId, uuid, code, desc)
	})
	if err != nil {
		logger.Warning(err)
	}

	err = cd.core.Status().ConnectChanged(func(hasValue bool, status int32) {
		if hasValue {
			cd.proxy.emitDeviceSignalStatus(cd.invokeId, status)
		}
	})
	if err != nil {
		logger.Warning(err)
	}

	cd.selected = true
}

func (cd *commonDevice) connectStatusChanged(fn func(hasValue bool, status int32)) error {
	cd.core.InitSignalExt(cd.sigLoop, true)

	cd.handlerInit = true
	return cd.core.Status().ConnectChanged(fn)
}

func (cd *commonDevice) removeStatusConnect() {
	if cd.handlerInit {
		cd.core.RemoveAllHandlers()
		cd.handlerInit = false
	}
}

func (cd *commonDevice) devDeSelect() {
	if cd.selected {
		cd.core.RemoveAllHandlers()
		cd.selected = false
	}
}

func (cd *commonDevice) name() (string, error) {
	return cd.core.Name().Get(0)
}

func (cd *commonDevice) claimed() (bool, error) {
	return cd.core.Claimed().Get(0)
}

func (cd *commonDevice) capability() (int32, error) {
	return cd.core.Capability().Get(0)
}

func (cd *commonDevice) status() (int32, error) {
	return cd.core.Status().Get(0)
}

func (cd *commonDevice) supportDevices() ([]string, error) {
	return cd.core.SupportedDevices().Get(0)
}

func (cd *commonDevice) defaultDevice() (string, error) {
	return cd.core.DefaultDevice().Get(0)
}

func (cd *commonDevice) serviceName() string {
	return cd.service
}

func (cd *commonDevice) claim(claimed bool) error {
	return cd.core.Claim(0, claimed)
}

func (cd *commonDevice) startEnroll(user string, faceName string) error {
	return cd.core.StartEnroll(0, user, faceName)
}

func (cd *commonDevice) stopEnroll() error {
	return cd.core.StopEnroll(0)
}

func (cd *commonDevice) startVerify(user string, timeout int) error {
	return cd.core.StartVerify(0, user, int32(timeout))
}

func (cd *commonDevice) stopVerify() error {
	return cd.core.StopVerify(0)
}

func (cd *commonDevice) listFaces(user string) ([]string, error) {
	return cd.core.ListFaces(0, user)
}

func (cd *commonDevice) deleteFace(user string, face string) error {
	return cd.core.DeleteFace(0, user, face)
}

func (cd *commonDevice) renameFace(user string, oldFace string, newFace string) error {
	return cd.core.RenameFace(0, user, oldFace, newFace)
}

func (cd *commonDevice) deleteFaces(user string) error {
	return cd.core.DeleteFaces(0, user)
}

func (cd *commonDevice) setDefaultDevice(device string) error {
	return cd.core.SetDefaultDevice(0, device)
}

func (cd *commonDevice) getShareMemInfo() (string, string, int32, error) {
	return cd.core.GetShareMemInfo(0)
}
