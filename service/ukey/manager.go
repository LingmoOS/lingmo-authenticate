package ukey

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/godbus/dbus"
	ofdbus "github.com/linuxdeepin/go-dbus-factory/org.freedesktop.dbus"
	"pkg.deepin.io/dde/authentication/service/authcommon"
	"github.com/linuxdeepin/go-lib/dbusutil"
)

//go:generate dbusutil-gen em -type Manager

const (
	dbusUKeyPath      = "/com/deepin/daemon/Authenticate/UKey"
	dbusUKeyInterface = "com.deepin.daemon.Authenticate.UKey"
	defaultConfigFile = "/var/lib/deepin/authenticate/ukey.json"
)

const InterfacesDir = "/usr/share/deepin-authentication/interfaces/"

type verificationInfo struct {
	id                string
	serviceName       string
	useDefaultService bool
	username          string
	uuid              string
	sessionPath       string
	dev               Device
}

type ValidDeviceInfo struct {
	Name        string
	Capability  int32
	Type        int32
	ServiceName string
}

type Manager struct {
	id         uint
	idMux      sync.Mutex
	service    *dbusutil.Service
	sysSigLoop *dbusutil.SignalLoop
	dbusDaemon ofdbus.DBus
	watcher    *fsnotify.Watcher

	uKeyServiceMap    map[string]*authcommon.InterfaceConfigWithFileName
	uKeyServiceMapMux sync.Mutex

	quitServiceMap    map[string]string
	quitServiceMapMux sync.Mutex

	// props
	ValidDevices  string
	DefaultDevice string

	verificationInfoMap    map[string]*verificationInfo
	verificationInfoMapMux sync.Mutex

	// nolint
	signals *struct {
		VerifyResult struct {
			id  string
			msg string
		}
		State struct {
			id    string
			state int
		}
	}
}

func newManager(service *dbusutil.Service) *Manager {
	sysBus := service.Conn()

	m := &Manager{
		service:             service,
		sysSigLoop:          dbusutil.NewSignalLoop(sysBus, 10),
		dbusDaemon:          ofdbus.NewDBus(sysBus),
		verificationInfoMap: make(map[string]*verificationInfo),
		uKeyServiceMap:      make(map[string]*authcommon.InterfaceConfigWithFileName),
		quitServiceMap:      make(map[string]string),
	}
	return m
}

func (m *Manager) init() {
	m.loadAllConfigs()
	m.loadDefaultDevice()
	m.updateValidDevice()
	m.initWatcher()
	m.listenSignals()
	m.sysSigLoop.Start()
}

func (m *Manager) genId() string {
	m.idMux.Lock()
	defer m.idMux.Unlock()
	m.id++
	return strconv.FormatUint(uint64(m.id), 10)
}

func (m *Manager) initWatcher() {
	var err error
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		logger.Warning(err)
	}
	err = m.watcher.Add(authcommon.InterfacesDir)
	if err != nil {
		logger.Debugf("when monitor %s err: %s", authcommon.InterfacesDir, err)
	}

	go m.dispatchFsEvents()
}

func (m *Manager) dispatchFsEvents() {
	for {
		select {
		case ev := <-m.watcher.Events:
			logger.Debugf("file %s changed %s", ev.Name, ev.Op)

			if ev.Op&fsnotify.Create != 0 {
				m.loadServiceConfigAndUpdateDefaultDevice(ev.Name)
				m.updateValidDevice()
			}

			if ev.Op&fsnotify.Write != 0 {
				m.updateDeviceAndDefaultDevice(ev.Name)
				m.updateValidDevice()
			}

			if ev.Op&fsnotify.Remove != 0 {
				m.removeConfigAndUpdateDefaultDevice(ev.Name)
				m.updateValidDevice()
			}
		case err := <-m.watcher.Errors:
			logger.Warning("receive file watcher error: ", err)
		}
	}
}

func (m *Manager) markServiceQuited(id, service string) {
	m.quitServiceMapMux.Lock()
	defer m.quitServiceMapMux.Unlock()

	m.quitServiceMap[id] = service
}

func (m *Manager) getMarkedServiceIds(service string) []string {
	var ids []string
	m.quitServiceMapMux.Lock()
	defer m.quitServiceMapMux.Unlock()
	for key, value := range m.quitServiceMap {
		if value == service {
			ids = append(ids, key)
		}
	}
	return ids
}

func (m *Manager) deleteMarkedService(ids []string) {
	if ids == nil {
		return
	}

	m.quitServiceMapMux.Lock()
	defer m.quitServiceMapMux.Unlock()

	for _, id := range ids {
		delete(m.quitServiceMap, id)
	}
}

func (m *Manager) listenSignals() {
	m.dbusDaemon.InitSignalExt(m.sysSigLoop, true)
	_, err := m.dbusDaemon.ConnectNameOwnerChanged(func(name string, oldOwner string, newOwner string) {
		if newOwner == "" &&
			oldOwner != "" {
			// service name lost
			infoArray := m.selectVerificationInfos(func(v *verificationInfo) bool {
				if v.dev.handleNameLost(name) {
					return true
				}
				return false
			})

			for _, info := range infoArray {
				m.emitSignalState(info.id, int(authcommon.UKeyStateDeviceNotExist))
				m.markServiceQuited(info.id, name)
				info.dev.devDeselect()
			}
		} else if newOwner != "" && oldOwner == "" {
			// service restart, emit state to all verification that marked
			ids := m.getMarkedServiceIds(name)
			if ids != nil {
				for _, id := range ids {
					m.emitSignalState(id, int(authcommon.UKeyStateDeviceOk))
				}
				m.deleteMarkedService(ids)
			}
		}
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) updateValidDevice() {
	var deviceList []ValidDeviceInfo

	for _, config := range m.uKeyServiceMap {
		var devInfo ValidDeviceInfo
		dev, err := newCommonDevice(m, config.Service, dbus.ObjectPath(config.Path), config.Interface)
		if err != nil {
			continue
		}

		devInfo.Name, _ = dev.name()
		devInfo.Type, _ = dev.type0()
		devInfo.Capability, _ = dev.capability()
		devInfo.ServiceName = config.Service

		deviceList = append(deviceList, devInfo)
	}

	// 当结构中没有数据时,json.Marshal 会返回 `null`, 而不是 `""`
	if len(deviceList) == 0 {
		m.setPropValidDevices("")
		return
	}
	devList, err := json.Marshal(deviceList)
	if err != nil {
		logger.Warning("marshal deviceList err:", err)
	}
	m.setPropValidDevices(string(devList))
}

func (m *Manager) loadServiceConfigAndUpdateDefaultDevice(filename string) {
	config, err := authcommon.LoadInterfaceConfig(filename, authcommon.InterfaceTypeUKey)
	if err != nil {
		logger.Warning(err)
		return
	}

	configWithFile := authcommon.InterfaceConfigWithFileName{
		InterfaceConfig: config,
		FileName:        filename,
	}

	m.uKeyServiceMapMux.Lock()
	m.uKeyServiceMap[config.Service] = &configWithFile
	m.uKeyServiceMapMux.Unlock()

	if m.DefaultDevice == "" {
		m.loadDefaultDevice()
	}
}

func (m *Manager) updateDeviceAndDefaultDevice(filename string) {
	config, err := authcommon.LoadInterfaceConfig(filename, authcommon.InterfaceTypeUKey)
	if err != nil {
		logger.Warning(err)
		return
	}

	var oldServiceName string
	for _, uKeyConfig := range m.uKeyServiceMap {
		if uKeyConfig.FileName == filename {
			oldServiceName = uKeyConfig.Service
			uKeyConfig = &authcommon.InterfaceConfigWithFileName{
				InterfaceConfig: config,
				FileName:        filename,
			}
		}
	}

	if oldServiceName == m.DefaultDevice {
		m.selectDefaultDeviceFromMap()
	}
}

func (m *Manager) removeConfigAndUpdateDefaultDevice(filename string) {
	// 如果 filename 被删除,则寻找 filename 对应的 UKey 配置,并将其删除
	for service, uKeyConfig := range m.uKeyServiceMap {
		if uKeyConfig.FileName == filename {
			delete(m.uKeyServiceMap, service)
			if m.DefaultDevice == uKeyConfig.Service {
				m.setPropDefaultDevice("")
				m.selectDefaultDeviceFromMap()
			}
			return
		}
	}
}

func (m *Manager) loadAllConfigs() {
	configs, err := authcommon.GetInterfaceConfigs(InterfacesDir, authcommon.InterfaceTypeUKey)
	if err != nil {
		logger.Warning("load interface config err:", err)
	}

	for _, config := range configs {
		m.uKeyServiceMap[config.Service] = config
	}
}

func (m *Manager) loadDefaultDevice() {
	if m.loadDefaultDeviceFromFile() {
		return
	}
	m.selectDefaultDeviceFromMap()
}

func (m *Manager) selectDefaultDeviceFromMap() {
	if len(m.uKeyServiceMap) > 0 {
		for service, _ := range m.uKeyServiceMap {
			m.setPropDefaultDevice(service)
			break
		}
	}
}

func (m *Manager) loadDefaultDeviceFromFile() bool {
	config, err := loadDefaultDeviceConfig(defaultConfigFile)
	if err != nil {
		return false
	}
	for _, uKeyConfig := range m.uKeyServiceMap {
		if uKeyConfig.Service == config.DefaultDevice {
			m.setPropDefaultDevice(config.DefaultDevice)
			return true
		}
	}

	return false
}

func (m *Manager) GetInterfaceName() string {
	return dbusUKeyInterface
}

func (m *Manager) getDefaultDevice() (Device, error) {
	for _, config := range m.uKeyServiceMap {
		if config.Service == m.DefaultDevice {
			return newCommonDevice(m, config.Service, dbus.ObjectPath(config.Path), config.Interface)
		}
	}
	return nil, errors.New("empty default device")
}

func (m *Manager) deleteVerificationInfo(id string) {
	m.verificationInfoMapMux.Lock()
	defer m.verificationInfoMapMux.Unlock()
	delete(m.verificationInfoMap, id)
}

func (m *Manager) selectVerificationInfos(fn func(*verificationInfo) bool) []*verificationInfo {
	m.verificationInfoMapMux.Lock()
	defer m.verificationInfoMapMux.Unlock()
	var vArray []*verificationInfo
	for _, v := range m.verificationInfoMap {
		if fn(v) {
			vArray = append(vArray, v)
		}
	}
	return vArray
}

func (m *Manager) getVerificationInfo(id string) (*verificationInfo, error) {
	m.verificationInfoMapMux.Lock()
	defer m.verificationInfoMapMux.Unlock()
	if verificationInfo, ok := m.verificationInfoMap[id]; ok {
		return verificationInfo, nil
	}
	return nil, fmt.Errorf("not found group %s's info", id)
}

func (m *Manager) emitSignalVerifyResult(id string, msg string) {
	m.service.Emit(m, "VerifyResult", id, msg)
}

func (m *Manager) emitSignalState(id string, state int) {
	m.service.Emit(m, "State", id, state)
}

func (m *Manager) genUKeyVerifyMsg(uuid string, uKeyResult authcommon.UKeyResType, description string) (string, error) {
	res := authcommon.UKeyResult{Id: uuid, Result: uKeyResult, Description: description}
	bytes, err := json.Marshal(res)
	if err != nil {
		return "", err
	}
	return string(bytes), err
}

func (m *Manager) getUKeyConfig(serviceName string) *authcommon.InterfaceConfig {
	for _, config := range m.uKeyServiceMap {
		if config.Service == serviceName {
			return &authcommon.InterfaceConfig{
				Service:   config.Service,
				Path:      config.Path,
				Interface: config.Interface,
			}
		}
	}
	return nil
}

func (m *Manager) newDevice(serviceName string, useDefaultService bool) (Device, error) {
	if useDefaultService {
		return m.getDefaultDevice()
	}

	config := m.getUKeyConfig(serviceName)
	if config == nil {
		return nil, fmt.Errorf("not found ukey service with %s", serviceName)
	}
	device, err := newCommonDevice(m, config.Service, dbus.ObjectPath(config.Path), config.Interface)

	return device, err
}
