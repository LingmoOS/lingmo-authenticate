package face

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/godbus/dbus"

	ofdbus "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.dbus"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"

	ac "pkg.deepin.io/dde/authentication/service/authcommon"
	"pkg.deepin.io/dde/authentication/service/task"
)

const (
	dBusFacePath      = "/com/deepin/daemon/Authenticate/Face"
	dBusFaceInterface = "com.lingmo.daemon.Authenticate.Face"
	defaultConfigFile = "/var/lib/deepin/authenticate/face.json"
)

type DeviceStatus int

const (
	DeviceStatusDeviceDisconnect DeviceStatus = iota
	DeviceStatusOk
	DeviceStatusServiceException
	DeviceStatusDeviceBusy
)

type callerInfo struct {
	id          string
	sender      dbus.Sender
	username    string
	uuid        string
	serviceName string
	shmSockPath string
	shmKey      string
	shmSize     int32
	dev         device
}

type ServiceInfo struct {
	Name             string
	Service          string
	SupportedDevices []string
	DefaultDevice    string
	Capability       int
	Status           DeviceStatus
}

type ServiceList struct {
	Config []ServiceInfo
}

type Manager struct {
	id   uint
	idMu sync.Mutex

	service    *dbusutil.Service
	sysSigLoop *dbusutil.SignalLoop
	dBusDaemon ofdbus.DBus
	watcher    *fsnotify.Watcher

	deviceMap     map[string]*ac.InterfaceConfigWithFileName
	deviceMapRwMu sync.RWMutex

	callInfoMap     map[string]*callerInfo
	callInfoMapRwMu sync.RWMutex

	existDevice []device

	defaultMap     map[string]string
	defaultMapRwMu sync.RWMutex

	DefaultDevice  string
	DefaultService string
	ServiceList    string

	// nolint
	signals *struct {
		EnrollStatus struct {
			id   string
			user string
			code int
			msg  string
		}
		VerifyStatus struct {
			id   string
			user string
			code int
			msg  string
		}
		DeviceStatus struct {
			serviceName string
			code        int
		}
	}
}

func (m *Manager) GetInterfaceName() string {
	return dBusFaceInterface
}

func newManager(service *dbusutil.Service) *Manager {
	sysBus := service.Conn()

	m := &Manager{
		service:     service,
		dBusDaemon:  ofdbus.NewDBus(sysBus),
		deviceMap:   make(map[string]*ac.InterfaceConfigWithFileName),
		callInfoMap: make(map[string]*callerInfo),
		defaultMap:  make(map[string]string),
		sysSigLoop:  dbusutil.NewSignalLoop(sysBus, 10),
	}
	return m
}

func (m *Manager) genId() uint {
	m.idMu.Lock()
	defer m.idMu.Unlock()

	id := m.id
	m.id += 1
	return id
}

func (m *Manager) updateProps() {
	m.loadServiceList()
	m.loadDefaultService()

	// update DefaultDevice according to DefaultService
	m.defaultMapRwMu.RLock()
	defer m.defaultMapRwMu.RUnlock()
	m.setPropDefaultDevice(m.defaultMap[m.DefaultService])
}

func (m *Manager) init() {
	m.sysSigLoop.Start()

	m.initWatcher()
	m.loadAllDevices()
	m.updateProps()
	m.listenPropDeviceStatus()
}

func (m *Manager) listenPropDeviceStatus() {
	for _, dev := range m.existDevice {
		serviceName := dev.serviceName()

		err := dev.connectStatusChanged(func(serviceName string) func(hasValue bool, status int32) {
			return func(hasValue bool, status int32) {
				if hasValue {
					m.updateProps()
					m.emitSignalDeviceStatus(serviceName, status)
				}
			}
		}(serviceName))
		if err != nil {
			logger.Warning(err)
		}
	}

	// 添加阻塞型任务，在 'InterfaceConfigChanged' 信号触发之后执行移除对设备状态的监听
	task.GetTaskManager().AddSignalTask("InterfaceConfigChanged", "InterfaceConfigChanged", func(_ string, _ ...interface{}) bool {
		for _, dev := range m.existDevice {
			dev.removeStatusConnect()
		}
		return true
	}, true)
}

func (m *Manager) initWatcher() {
	var err error
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		logger.Warning(err)
		return
	}
	err = m.watcher.Add(ac.InterfacesDir)
	if err != nil {
		logger.Debugf("when monitor %s err: %s", ac.InterfacesDir, err)
	}

	go m.dispatchFsEvents()
}

func (m *Manager) dispatchFsEvents() {
	for {
		select {
		case ev := <-m.watcher.Events:
			logger.Debugf("file %s changed %s", ev.Name, ev.Op)

			if ev.Op&fsnotify.Create != 0 || ev.Op&fsnotify.Write != 0 || ev.Op&fsnotify.Remove != 0 {
				m.loadAllDevices()
				m.updateProps()
				m.listenPropDeviceStatus()
			}

		case err := <-m.watcher.Errors:
			logger.Warning("receive file watcher error: ", err)
		}
	}
}

func (m *Manager) loadDefaultService() {
	defaultConfigFn := func() string {
		var defaultService string

		for _, dev := range m.existDevice {
			status, err := dev.status()
			if err == nil && DeviceStatus(status) != DeviceStatusDeviceDisconnect {
				defaultService = dev.serviceName()
				break
			}
		}
		return defaultService
	}

	config, err := loadDefaultDeviceConfig(defaultConfigFile)
	if err != nil {
		logger.Warningf("load file %s err: %s, reset default service", defaultConfigFile, err)
		m.setPropDefaultService(defaultConfigFn())
		return
	}

	m.deviceMapRwMu.RLock()
	defer m.deviceMapRwMu.RUnlock()

	var defaultService string
	if _, ok := m.deviceMap[config.DefaultService]; !ok {
		logger.Warningf("service %s is not exist, reset default service", config.DefaultService)
		defaultService = defaultConfigFn()
	} else {
		defaultService = config.DefaultService
	}

	m.setPropDefaultService(defaultService)
}

func (m *Manager) loadServiceList() {
	m.deviceMapRwMu.RLock()
	defer m.deviceMapRwMu.RUnlock()

	var serviceList ServiceList

	for _, dev := range m.existDevice {
		var err error
		var name string
		var devices []string
		var defaultDevice string
		var capability int32
		var status int32

		ac.SyncCallWithTimeout(time.Second*3, func(...interface{}) error {
			name, err = dev.name()
			return err
		})
		if err != nil {
			continue
		}

		ac.SyncCallWithTimeout(time.Second*3, func(...interface{}) error {
			devices, err = dev.supportDevices()
			return err
		})
		if err != nil {
			continue
		}

		ac.SyncCallWithTimeout(time.Second*3, func(...interface{}) error {
			defaultDevice, err = dev.defaultDevice()
			return err
		})
		if err != nil {
			continue
		}

		ac.SyncCallWithTimeout(time.Second*3, func(...interface{}) error {
			capability, err = dev.capability()
			return err
		})
		if err != nil {
			continue
		}

		ac.SyncCallWithTimeout(time.Second*3, func(...interface{}) error {
			status, err = dev.status()
			return err
		})
		if err != nil {
			continue
		}

		serviceInfo := ServiceInfo{
			Name:             name,
			Service:          dev.serviceName(),
			SupportedDevices: devices,
			DefaultDevice:    defaultDevice,
			Capability:       int(capability),
			Status:           DeviceStatus(status),
		}

		serviceList.Config = append(serviceList.Config, serviceInfo)

		m.setDefaultInfo(dev.serviceName(), defaultDevice)
	}
	if len(serviceList.Config) == 0 {
		m.setPropServiceList("")
		return
	}

	bytes, err := json.Marshal(serviceList)
	if err != nil {
		logger.Warning(err)
		return
	}

	m.setPropServiceList(string(bytes))
}

func (m *Manager) setDefaultInfo(serviceName, device string) {
	m.defaultMapRwMu.Lock()
	defer m.defaultMapRwMu.Unlock()

	m.defaultMap[serviceName] = device
}

func (m *Manager) loadAllDevices() {
	configs, err := ac.GetInterfaceConfigs(ac.InterfacesDir, ac.InterfaceTypeFace)
	if err != nil {
		logger.Warning(err)
	}

	m.deviceMapRwMu.Lock()
	defer m.deviceMapRwMu.Unlock()

	for _, config := range configs {
		m.deviceMap[config.Service] = config
	}

	// 先执行信号 'InterfaceConfigChanged' 的任务，然后清空 existDevice 设备列表，后续重新添加 existDevice
	task.GetTaskManager().DoSignalTask("InterfaceConfigChanged")

	m.existDevice = make([]device, 0)

	for _, config := range m.deviceMap {
		dev, err := newCommonDevice(config.Service, dbus.ObjectPath(config.Path), config.Interface, m)
		if err != nil {
			logger.Warningf("new device %s err: %s", config.Service, err)
			continue
		}
		m.existDevice = append(m.existDevice, dev)
	}
}

func (m *Manager) genCallerInfo(sender dbus.Sender, username, serviceName string) (*callerInfo, error) {
	genId := m.genId()
	id := strconv.Itoa(int(genId))

	userInfo, err := ac.GetUserInfo(username)
	if err != nil {
		logger.Warningf("get user %s err: %s", username, err)
		return nil, err
	}
	callInfo := &callerInfo{
		id:          id,
		sender:      sender,
		username:    username,
		uuid:        userInfo.Uuid,
		serviceName: serviceName,
		dev:         nil,
	}

	dev, err := m.newDevice(serviceName)
	if err != nil {
		return nil, err
	}

	m.callInfoMapRwMu.Lock()
	defer m.callInfoMapRwMu.Unlock()

	m.callInfoMap[id] = callInfo

	callInfo.dev = dev
	return callInfo, nil
}

func (m *Manager) deleteCallerInfo(id string) {
	m.callInfoMapRwMu.Lock()
	defer m.callInfoMapRwMu.Unlock()

	delete(m.callInfoMap, id)
}

func (m *Manager) getCallerInfo(id string) (*callerInfo, error) {
	m.callInfoMapRwMu.RLock()
	defer m.callInfoMapRwMu.RUnlock()

	if caller, ok := m.callInfoMap[id]; ok {
		return caller, nil
	}

	return nil, fmt.Errorf("not found the information for %s", id)
}

func (m *Manager) newDevice(serviceName string) (device, error) {
	m.deviceMapRwMu.RLock()
	defer m.deviceMapRwMu.RUnlock()

	if serviceName == "" {
		serviceName = m.DefaultService
	}

	var serviceConfig *ac.InterfaceConfigWithFileName
	var ok bool
	if serviceConfig, ok = m.deviceMap[serviceName]; !ok {
		logger.Warningf("get service config %s err: not found", serviceName)
		return nil, fmt.Errorf("get service config %s err: not found", serviceName)
	}

	dev, err := newCommonDevice(serviceConfig.Service, dbus.ObjectPath(serviceConfig.Path), serviceConfig.Interface, m)
	if err != nil {
		logger.Warningf("new device %s err: %s", serviceName, err)
		return nil, err
	}
	return dev, nil
}

func (m *Manager) isDeviceClaimed(serviceName string) bool {
	dev, err := m.newDevice(serviceName)
	if err != nil {
		return true
	}

	claimed, err := dev.claimed()
	if err != nil {
		return true
	}

	return claimed
}

func (m *Manager) emitSignalVerifyStatus(id string, user string, code int32, msg string) {
	err := m.service.Emit(m, "VerifyStatus", id, user, code, msg)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) emitSignalEnrollStatus(id string, user string, code int32, msg string) {
	err := m.service.Emit(m, "EnrollStatus", id, user, code, msg)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) emitSignalDeviceStatus(serviceName string, code int32) {
	err := m.service.Emit(m, "DeviceStatus", serviceName, code)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) emitDeviceSignalEnrollStatus(invokedId string, uuid string, code int32, msg string) {
	caller, err := m.getCallerInfo(invokedId)
	if err != nil {
		logger.Warningf("can not found caller id: %s", invokedId)
		return
	}

	if caller.uuid == uuid {
		m.emitSignalEnrollStatus(invokedId, caller.username, code, msg)
	} else {
		logger.Debugf("caller id %s's uuid %s not match with %s", invokedId, uuid, caller.uuid)
	}
}

func (m *Manager) emitDeviceSignalVerifyStatus(invokeId string, uuid string, code int32, msg string) {
	_, err := m.getCallerInfo(invokeId)
	if err != nil {
		logger.Warningf("can not found caller id: %s", invokeId)
		return
	}

	user, err := ac.GetUserNameByUuid(uuid)
	if err != nil {
		logger.Debugf("GetUserNameByUuid err: %s", err)
		return
	}

	m.emitSignalVerifyStatus(invokeId, user, code, msg)
}

func (m *Manager) emitDeviceSignalStatus(invokedId string, code int32) {
	caller, err := m.getCallerInfo(invokedId)
	if err != nil {
		logger.Warningf("can not found caller id: %s", invokedId)
		return
	}

	if DeviceStatus(code) == DeviceStatusDeviceDisconnect {
		m.emitSignalVerifyStatus(invokedId, caller.username, int32(ac.FaceVerifyException), "")
	}

	if DeviceStatus(code) == DeviceStatusDeviceDisconnect {
		m.emitSignalEnrollStatus(invokedId, caller.username, int32(ac.FaceEnrollException), "")
	}

	m.emitSignalDeviceStatus(caller.serviceName, code)
}

func (m *Manager) isConcernedSignalNameLost(id string, paras ...interface{}) (concerned bool, needDel bool, caller *callerInfo) {
	caller, err := m.getCallerInfo(id)
	if err != nil {
		logger.Warning(err)
		return false, true, nil
	}

	if len(paras) == 1 && paras[0] == caller.sender {
		return true, true, caller
	}
	return false, false, nil
}

func (m *Manager) getSigLoop() *dbusutil.SignalLoop {
	return m.sysSigLoop
}
