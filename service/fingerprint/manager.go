package fingerprint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus"
	accounts "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.accounts"
	huawei_fprint "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.huawei.fingerprint"
	fprintd "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/net.reactivated.fprint"
	ofdbus "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.dbus"
	"github.com/LingmoOS/velora-api/polkit"
	"pkg.deepin.io/dde/authentication/pkg/fingerprint"
	pkgfp "pkg.deepin.io/dde/authentication/pkg/fingerprint"
	ac "pkg.deepin.io/dde/authentication/service/authcommon"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/strv"
)

const (
	dbusFingerPrintPath      = "/com/deepin/daemon/Authenticate/Fingerprint"
	dbusFingerPrintInterface = "com.lingmo.daemon.Authenticate.Fingerprint"

	actionIdEnroll = "com.deepin.daemon.authenticate.Fingerprint.enroll"
	actionIdDelete = "com.deepin.daemon.authenticate.Fingerprint.delete-enrolled-fingers"
)

//go:generate dbusutil-gen -type Manager manager.go
//go:generate dbusutil-gen em -type Manager

type Manager struct {
	service        *dbusutil.Service
	sysSigLoop     *dbusutil.SignalLoop
	fprintdManager fprintd.Manager
	huaweiFprint   huawei_fprint.Fingerprint
	dbusDaemon     ofdbus.DBus
	accounts       accounts.Accounts
	config         Config

	claimInfo struct {
		sender   dbus.Sender
		userInfo UserInfo
	}

	allDevices []Device

	defaultDevice  Device       // -> DefaultDevice prop
	deviceInfoList []DeviceInfo // -> Devices prop

	PropsMu sync.RWMutex
	// props
	DefaultDevice string
	Devices       string

	// nolint
	signals *struct {
		EnrollStatus struct {
			id   string
			code int32
			msg  string
		}

		VerifyStatus struct {
			id   string
			code int32
			msg  string
		}

		Touch struct {
			id      string
			pressed bool
		}
	}
}

func (*Manager) GetInterfaceName() string {
	return dbusFingerPrintInterface
}

func newManager(service *dbusutil.Service) (*Manager, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	m := &Manager{
		service:        service,
		sysSigLoop:     dbusutil.NewSignalLoop(sysBus, 10),
		dbusDaemon:     ofdbus.NewDBus(sysBus),
		fprintdManager: fprintd.NewManager(sysBus),
		huaweiFprint:   huawei_fprint.NewFingerprint(sysBus),
		accounts:       accounts.NewAccounts(sysBus),
	}
	return m, nil
}

func (m *Manager) init() {
	m.sysSigLoop.Start()
	m.listenSignals()
	m.initFakeDevice()
	m.initHuaweiDevice()
	m.initCommonDevices()
	m.initFprintdDevices()
	m.updatePropDevices()

	err := loadConfig(configFile, &m.config)
	if err != nil && !os.IsNotExist(err) {
		logger.Warning(err)
	}

	if len(m.deviceInfoList) > 0 {
		var devInfo DeviceInfo

		if m.config.DefaultDevice != "" {
			for _, deviceInfo := range m.deviceInfoList {
				if deviceInfo.Name == m.config.DefaultDevice {
					devInfo = deviceInfo
					break
				}
			}
		}
		if devInfo.Name == "" {
			devInfo = m.deviceInfoList[0]
		}

		err := m.setDefaultDeviceWithInfo(devInfo)
		if err != nil {
			logger.Warning(err)
		}
	}
}

func (m *Manager) listenSignals() {
	m.dbusDaemon.InitSignalExt(m.sysSigLoop, true)
	_, err := m.dbusDaemon.ConnectNameOwnerChanged(func(name string, oldOwner string, newOwner string) {
		if newOwner == "" &&
			oldOwner != "" &&
			name == oldOwner &&
			strings.HasPrefix(name, ":") {
			// uniq name lost
			//logger.Debug("uniq name lost", name)
			for _, device := range m.allDevices {
				if device.handleNameLost(name) {
					break
				}
			}
		}
	})
	if err != nil {
		logger.Warning(err)
	}
}

var FakeDeviceEnabled = ""

func (m *Manager) initFakeDevice() {
	if FakeDeviceEnabled == "1" {
		d := newFakeDevice(m)
		m.allDevices = append(m.allDevices, d)
	}
}

func (m *Manager) initHuaweiDevice() {
	has, err := m.hasHuaweiDevice()
	if err != nil {
		logger.Warning(err)
	}

	if has {
		d := newHuaweiDevice(m)
		m.allDevices = append(m.allDevices, d)
	}
}

func (m *Manager) hasHuaweiDevice() (has bool, err error) {
	activatableNames, err := m.dbusDaemon.ListActivatableNames(0)
	if err != nil {
		return false, err
	}
	if !strv.Strv(activatableNames).Contains(m.huaweiFprint.ServiceName_()) {
		return false, nil
	}

	logger.Debug("start huawei SearchDevice")
	ch := make(chan struct{})
	go func() {
		has, err = m.huaweiFprint.SearchDevice(0)
		ch <- struct{}{}
	}()

	select {
	case <-ch:
	case <-time.After(DeviceTimeoutSeconds * time.Second):
		logger.Debug("huawei SearchDevice timeout")
	}

	logger.Debug("huawei SearchDevice res", has)
	return
}

func (m *Manager) initCommonDevices() {
	ifcConfigs, err := getInterfaceConfigs(InterfaceTypeFingerprint)
	if err != nil {
		logger.Warning(err)
		return
	}

	for _, ifcCfg := range ifcConfigs {
		d, err := newCommonDevice(m, ifcCfg.Service, dbus.ObjectPath(ifcCfg.Path), ifcCfg.Interface)
		if err != nil {
			logger.Warning(err)
			continue
		}
		m.allDevices = append(m.allDevices, d)
	}
}

func (m *Manager) initFprintdDevices() {
	devices, err := m.fprintdManager.GetDevices(0)
	if err != nil {
		logger.Warning(err)
		return
	}
	for _, devPath := range devices {
		d, err := newFprintdDevice(m, devPath)
		if err != nil {
			logger.Warning(err)
			continue
		}
		m.allDevices = append(m.allDevices, d)
	}
}

func (m *Manager) updatePropDevices() {
	var devInfoList []DeviceInfo
	for _, device := range m.allDevices {
		di, err := getDeviceInfo(device)
		if err != nil {
			logger.Warning(err)
			continue
		}
		devInfoList = append(devInfoList, di)
	}
	devInfosBytes, err := json.Marshal(devInfoList)
	if err != nil {
		logger.Warning(err)
		return
	}
	devInfosStr := string(devInfosBytes)

	m.PropsMu.Lock()
	m.deviceInfoList = devInfoList
	m.setPropDevices(devInfosStr)
	m.PropsMu.Unlock()
}

func getDeviceInfo(dev Device) (DeviceInfo, error) {
	name, err := dev.name()
	if err != nil {
		return DeviceInfo{}, err
	}

	available, err := dev.available()
	if err != nil {
		logger.Warning(err)
	}

	capability, err := dev.capability()
	if err != nil {
		logger.Warning(err)
	}

	di := DeviceInfo{
		DeviceInfo: fingerprint.DeviceInfo{
			Name:       name,
			Available:  available,
			Capability: capability,
		},
		from: dev,
	}
	return di, nil
}

func (m *Manager) setDefaultDeviceWithInfo(devInfo DeviceInfo) error {
	if !devInfo.Available {
		return errors.New("device is unavailable")
	}

	dev := devInfo.from
	if dev.isClaimed() {
		err := errors.New("target default device is claimed")
		logger.Warning(err)
		return err
	}

	oldDev := m.defaultDevice
	if oldDev != nil {
		if oldDev.isClaimed() {
			return errors.New("old default device is claimed")
		}

		oldDev.deselect()
	}

	dev.select0()
	m.defaultDevice = dev
	m.setPropDefaultDevice(devInfo.Name)
	return nil
}

func (m *Manager) SetDefaultDevice(deviceName string) *dbus.Error {
	logger.Debug("SetDefaultDevice", deviceName)
	err := m.setDefaultDevice(deviceName)
	return dbusutil.ToError(err)
}

func (m *Manager) setDefaultDevice(deviceName string) error {
	var targetDevInfo DeviceInfo

	m.PropsMu.Lock()
	defer m.PropsMu.Unlock()

	for _, deviceInfo := range m.deviceInfoList {
		if deviceInfo.Name == deviceName {
			targetDevInfo = deviceInfo
			break
		}
	}

	if targetDevInfo.Name == "" {
		return fmt.Errorf("not found device %q", deviceName)
	}

	err := m.setDefaultDeviceWithInfo(targetDevInfo)
	if err != nil {
		return err
	}

	m.config.DefaultDevice = targetDevInfo.Name
	err = m.saveConfig()
	if err != nil {
		return err
	}

	return nil
}

func (m *Manager) saveConfig() error {
	configDir := filepath.Dir(configFile)
	err := os.MkdirAll(configDir, 0755)
	if err != nil {
		return err
	}
	err = saveConfig(configFile, &m.config)
	return err
}

func (m *Manager) getDefaultDevice() Device {
	m.PropsMu.Lock()
	defer m.PropsMu.Unlock()

	return m.defaultDevice
}

type MsgMap map[string]interface{}

func (msgMap MsgMap) toString() (string, error) {
	if len(msgMap) == 0 {
		return "", nil
	}
	msgBytes, err := json.Marshal(msgMap)
	if err != nil {
		return "", err
	}
	return string(msgBytes), nil
}

func (m *Manager) emitSignalEnrollStatus(username string, code int, msg MsgMap) {
	msgStr, err := msg.toString()
	if err != nil {
		logger.Warning(err)
		return
	}
	m.emitSignalEnrollStatusRaw(username, code, msgStr)
}

func (m *Manager) emitSignalEnrollStatusRaw(username string, code int, msg string) {
	logger.Debugf("emit signal EnrollStatus username: %s, code: %s, msg: %s",
		username, pkgfp.EnrollStatusToString(code), msg)
	err := m.service.Emit(m, "EnrollStatus", username, int32(code), msg)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) emitSignalVerifyStatus(username string, code int, msg MsgMap) {
	msgStr, err := msg.toString()
	if err != nil {
		logger.Warning(err)
		return
	}
	m.emitSignalVerifyStatusRaw(username, code, msgStr)
}

func (m *Manager) emitSignalVerifyStatusRaw(username string, code int, msg string) {
	logger.Debugf("emit signal VerifyStatus username: %s, code: %s, msg: %s",
		username, pkgfp.VerifyStatusToString(code), msg)
	err := m.service.Emit(m, "VerifyStatus", username, int32(code), msg)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) getUserInfo(username string) (userInfo UserInfo, err error) {
	if username == pkgfp.EmptyUsername {
		userInfo = UserInfo{
			name: pkgfp.EmptyUsername,
			uuid: pkgfp.EmptyUUID,
		}
		return
	}

	userPath, err := m.accounts.FindUserByName(0, username)
	if err != nil {
		return
	}

	sysBus := m.sysSigLoop.Conn()
	userObj, err := accounts.NewUser(sysBus, dbus.ObjectPath(userPath))
	if err != nil {
		return
	}

	uuid, err := userObj.UUID().Get(0)
	if err != nil {
		return
	}
	if uuid == "" {
		err = fmt.Errorf("user %q uuid is empty", username)
		return
	}
	userInfo.name = username
	userInfo.uuid = uuid
	return
}

func (m *Manager) findUserByUUID(uuid string) (userInfo UserInfo, err error) {
	userList, err := m.accounts.UserList().Get(0)
	if err != nil {
		return
	}

	sysBus := m.sysSigLoop.Conn()
	var userObj accounts.User
	var curUUID string
	for _, userPath := range userList {
		userObj, err = accounts.NewUser(sysBus, dbus.ObjectPath(userPath))
		if err != nil {
			logger.Warning(err)
			continue
		}

		curUUID, err = userObj.UUID().Get(0)
		if err != nil {
			logger.Warning(err)
			continue
		}

		if curUUID == uuid {
			username, _ := userObj.UserName().Get(0)

			userInfo.name = username
			userInfo.uuid = uuid

			return
		}
	}

	err = fmt.Errorf("uuid %s not found", uuid)
	return
}

var errNotFoundDevice = errors.New("not found device")

func (m *Manager) Claim(sender dbus.Sender, username string, claimed bool) *dbus.Error {
	logger.Debugf("sender: %s", string(sender))
	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	userInfo, err := m.getUserInfo(username)
	if err != nil {
		return dbusutil.ToError(err)
	}

	if claimed {
		// 释放原来的占用
		if dev.isClaimed() {
			err = dev.claim(string(m.claimInfo.sender), m.claimInfo.userInfo, false)
			if err != nil {
				return dbusutil.ToError(err)
			}
		}

		// 重新占用
		err = dev.claim(string(sender), userInfo, true)
		if err != nil {
			return dbusutil.ToError(err)
		}

		m.claimInfo = struct {
			sender   dbus.Sender
			userInfo UserInfo
		}{
			sender:   sender,
			userInfo: userInfo,
		}
	} else {
		err = dev.claim(string(sender), userInfo, claimed)
		return dbusutil.ToError(err)
	}

	return nil
}

func (m *Manager) Enroll(sender dbus.Sender, finger string) *dbus.Error {
	err := polkit.CheckAuth(actionIdEnroll, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	err = dev.checkClaimed(string(sender))
	if err != nil {
		return dbusutil.ToError(err)
	}

	err = dev.enroll(finger)
	return dbusutil.ToError(err)
}

func (m *Manager) StopEnroll(sender dbus.Sender) *dbus.Error {
	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	err := dev.checkClaimed(string(sender))
	if err != nil {
		return dbusutil.ToError(err)
	}

	ch := make(chan struct{})
	go func() {
		err = dev.stopEnroll()
		ch <- struct{}{}
	}()
	timeout := checkTimeout(ch)
	if timeout {
		err = errors.New("StopEnroll timeout")
	}

	return dbusutil.ToError(err)
}

func (m *Manager) Verify(sender dbus.Sender, finger string) *dbus.Error {
	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	err := dev.checkClaimed(string(sender))
	if err != nil {
		return dbusutil.ToError(err)
	}

	err = dev.verify(finger)
	return dbusutil.ToError(err)
}

func (m *Manager) StopVerify(sender dbus.Sender) *dbus.Error {
	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	err := dev.checkClaimed(string(sender))
	if err != nil {
		return dbusutil.ToError(err)
	}
	ch := make(chan struct{})
	go func() {
		err = dev.stopVerify()
		ch <- struct{}{}
	}()
	timeout := checkTimeout(ch)
	if timeout {
		err = errors.New("StopVerify timeout")
	}

	return dbusutil.ToError(err)
}

func (m *Manager) DeleteFinger(sender dbus.Sender, username, finger string) *dbus.Error {
	err := polkit.CheckAuth(actionIdDelete, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	userInfo, err := m.getUserInfo(username)
	if err != nil {
		return dbusutil.ToError(err)
	}

	ch := make(chan struct{})
	go func() {
		err = dev.deleteFinger(userInfo, finger)
		ch <- struct{}{}
	}()
	timeout := checkTimeout(ch)
	if timeout {
		err = errors.New("DeleteFinger timeout")
	}

	return dbusutil.ToError(err)
}

func (m *Manager) DeleteAllFingers(sender dbus.Sender, username string) *dbus.Error {
	err := polkit.CheckAuth(actionIdDelete, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	userInfo, err := m.getUserInfo(username)
	if err != nil {
		return dbusutil.ToError(err)
	}

	ch := make(chan struct{})
	go func() {
		err = dev.deleteAllFingers(userInfo)
		ch <- struct{}{}
	}()
	timeout := checkTimeout(ch)
	if timeout {
		err = errors.New("DeleteAllFingers timeout")
	}

	return dbusutil.ToError(err)
}

func (m *Manager) ListFingers(username string) (fingers []string, busErr *dbus.Error) {
	dev := m.getDefaultDevice()
	if dev == nil {
		return nil, dbusutil.ToError(errNotFoundDevice)
	}

	userInfo, err := m.getUserInfo(username)
	if err != nil {
		return nil, dbusutil.ToError(err)
	}

	ch := make(chan struct{})
	go func() {
		fingers, err = dev.listFingers(userInfo)
		ch <- struct{}{}
	}()
	timeout := checkTimeout(ch)
	if timeout {
		err = errors.New("ListFingers timeout")
		return nil, dbusutil.ToError(err)
	}

	return fingers, nil
}

func (m *Manager) RenameFinger(sender dbus.Sender, username, finger, newName string) *dbus.Error {
	if finger == newName {
		return dbusutil.ToError(errors.New("finger name has not changed"))
	}

	dev := m.getDefaultDevice()
	if dev == nil {
		return dbusutil.ToError(errNotFoundDevice)
	}

	userInfo, err := m.getUserInfo(username)
	if err != nil {
		return dbusutil.ToError(err)
	}

	ch := make(chan struct{})
	go func() {
		err = dev.renameFinger(userInfo, finger, newName)
		ch <- struct{}{}
	}()
	timeout := checkTimeout(ch)
	if timeout {
		err = errors.New("RenameFinger timeout")
	}
	return dbusutil.ToError(err)
}

func (m *Manager) PreAuthEnroll(sender dbus.Sender) *dbus.Error {
	logger.Debug("PreAuthEnroll", sender)
	err := polkit.CheckAuth(actionIdEnroll, string(sender), polkit.NewPolKitAuthDetails(ac.AuthenticationFlagPassword))
	if err != nil {
		return dbusutil.ToError(err)
	}

	dev := m.getDefaultDevice()
	if dev == nil {
		logger.Warning("not found default device")
		return nil
	}

	// wait device free, timeout 4s
	for i := 0; i < 20; i++ {
		isClaimed := dev.isClaimed()
		if !isClaimed {
			logger.Debug("PreAuthEnroll default device is free now")
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	logger.Warning("wait for the default device to become free timed out")

	return nil
}
