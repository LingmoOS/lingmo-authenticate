package charaDataManger

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/godbus/dbus"
	ofdbus "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.dbus"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/utils"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

const (
	dBusCharaMangerPath = "/com/lingmo/daemon/Authenticate/CharaManger"
	dBusCharaMangerface = "com.lingmo.daemon.Authenticate.CharaManger"
	charaInfoFile       = "/usr/share/deepin-authentication/chara/charaInfo"
)

type ActionInfo struct {
	UniqueSenderName    dbus.Sender // 发起方dbus唯一名称
	UniqueReceivernName dbus.Sender // 厂商dbus唯一名称
	ReceiverName        string      // 服务名
	ActionType          ActionType
	CharaType           CharaType
	ActionId            ActionId
	Code                StatusCode
	codeStatusChan      chan CodeStatusInfo
	CharaInfo           CharaInfo // 录入过程使用
}

type CharaDataManager struct {
	service *dbusutil.Service

	charaInfoMtx sync.RWMutex
	charaInfoMap map[Chara]*CharaInfo

	actionMapMtx sync.RWMutex
	// 以发起方（sender）+生物识别类型为key，以生成的actionID为value
	// 发起方负责释放
	actionMap map[string]*ActionInfo
	// 服务serverMap
	serverMap map[string]*CommonDriver
	serverMtx sync.RWMutex

	dbusDaemon ofdbus.DBus
	signalLoop *dbusutil.SignalLoop
	// 厂商服务变化的通知通道
	driverInfoChan chan DriverInfo
	// 特征值变化的通知通道
	charaInfoChan chan CharaInfo
}

var charaCommonData *CharaDataManager

func newManager(server *dbusutil.Service) *CharaDataManager {

	m := &CharaDataManager{
		service:      server,
		charaInfoMap: make(map[Chara]*CharaInfo),
		actionMap:    make(map[string]*ActionInfo),
		serverMap:    make(map[string]*CommonDriver),
		dbusDaemon:   ofdbus.NewDBus(server.Conn()),
		signalLoop:   dbusutil.NewSignalLoop(server.Conn(), 10),
	}
	return m
}

func GetCharaCommonDataManger() *CharaDataManager {
	return charaCommonData
}
func (m *CharaDataManager) init() {

	m.loadCharaInfo(charaInfoFile)
	m.loadService()
	m.initCharaAvailable()
	m.saveCharaInfoToFile()

}

func (m *CharaDataManager) loadCharaInfo(filename string) error {

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.Warning(err)
		return err
	}
	err = json.Unmarshal(content, &m.charaInfoMap)
	if err != nil {
		logger.Warning(err)
	}
	m.charaInfoMtx.Lock()
	defer m.charaInfoMtx.Unlock()
	for chara, _ := range m.charaInfoMap {
		m.charaInfoMap[chara].BAvailable = false
	}
	return err

}

func (m *CharaDataManager) loadService() {
	m.serverMtx.Lock()
	defer m.serverMtx.Unlock()
	// 开始前先清除，避免冗余数据
	for k := range m.serverMap {
		delete(m.serverMap, k)
	}

	configs, err := GetInterfaceConfigs(InterfacesDir, InterfaceTypeFace)
	if err != nil {
		logger.Warning(err)
	}

	configs1, err := GetInterfaceConfigs(InterfacesDir, InterfaceTypeIris)
	if err != nil {
		logger.Warning(err)
	}
	configs = append(configs, configs1...)

	for _, config := range configs {

		driver, err := newCommonDriver(config.Service, dbus.ObjectPath(config.Path), config.Interface, m)

		if err != nil {
			logger.Warningf("new driver%s err: %s", config.Service, err)
			continue
		}

		driver.Configer.Service = config.Service
		driver.Configer.Path = config.Path
		driver.Configer.Interface = config.Interface
		driver.Configer.Type = config.Type
		driver.Configer.StorageType = config.StorageType

		driver.init()
		m.serverMap[config.Service] = driver

		logger.Debugf("add driver name %s and chara type %d", config.Service, driver.DriverCharaType)

	}

}

func (m *CharaDataManager) SetCharaAndDriverInfoChan(charaInfoChan chan CharaInfo, driverInfoChan chan DriverInfo) {

	m.charaInfoChan = charaInfoChan
	m.driverInfoChan = driverInfoChan
	m.initlistenNameLost()
}

func (m *CharaDataManager) GetDriver(serverName string, charaType CharaType) (*CommonDriver, bool) {

	m.serverMtx.RLock()
	defer m.serverMtx.RUnlock()
	if driver, ok := m.serverMap[serverName]; ok {
		claim, err := driver.Core.Claim().Get(0)

		if err != nil {
			logger.Debug(err)
		}
		tempCharaType, err := m.serverMap[serverName].Core.CharaType().Get(0)
		if tempCharaType == 0 || err != nil {
			return nil, false
		}
		if CharaType(tempCharaType) != m.serverMap[serverName].DriverCharaType {
			m.HandleDriverCharaTypeChange(m.serverMap[serverName].Configer.Service, m.serverMap[serverName].DriverCharaType, CharaType(tempCharaType))
			m.serverMap[serverName].DriverCharaType = CharaType(tempCharaType)
		}

		if ok && driver.DriverCharaType&charaType != 0 {
			return driver, claim
		}
	}
	logger.Debugf("not found driver by server name %s and chara type %d", serverName, charaType)
	return nil, false
}

// 防止验证没有配备服务名
func (m *CharaDataManager) GetDefaultDriver(serverName string, charaType CharaType) (*CommonDriver, bool) {
	logger.Debugf("serverName %s,charaType=%d", serverName, charaType)
	if serverName != "" {
		if m.serverMap[serverName] == nil {
			return nil, false
		}
		tempCharaType, err := m.serverMap[serverName].Core.CharaType().Get(0)
		if tempCharaType == 0 || err != nil {
			return nil, false
		}
		if CharaType(tempCharaType) != m.serverMap[serverName].DriverCharaType {
			m.HandleDriverCharaTypeChange(m.serverMap[serverName].Configer.Service, m.serverMap[serverName].DriverCharaType, CharaType(tempCharaType))
			m.serverMap[serverName].DriverCharaType = CharaType(tempCharaType)
		}

		return m.serverMap[serverName], false
	}

	for key, driver := range m.serverMap {
		claim, err := driver.Core.Claim().Get(0)

		if err != nil {
			logger.Debug(err)
			continue
		}
		logger.Debug("claim", claim)
		logger.Debugf("driver.DriverCharaType %d", driver.DriverCharaType)

		tempCharaType, err := driver.Core.CharaType().Get(0)
		if tempCharaType == 0 || err != nil {
			continue
		}

		if CharaType(tempCharaType) != driver.DriverCharaType {
			m.HandleDriverCharaTypeChange(driver.Configer.Service, driver.DriverCharaType, CharaType(tempCharaType))
			driver.DriverCharaType = CharaType(tempCharaType)
		}
		if driver.DriverCharaType&charaType != 0 {
			return m.serverMap[key], claim
		}
	}
	logger.Debugf("not found driver by server name %s and chara type %d", serverName, charaType)
	return nil, false
}

func (m *CharaDataManager) GetCharaInfo(sender dbus.Sender, charaType CharaType, charaName string) *CharaInfo {

	uuid, err := m.GetUserUuidBySender(sender)

	if err != nil {
		logger.Warning(err)
		return nil
	}
	for _, charaInfo := range m.charaInfoMap {
		if charaInfo.Uuid == uuid && charaInfo.CharaType == charaType && charaInfo.CharaName == charaName {
			return charaInfo
		}
	}
	logger.Debugf("not found chara info by uuid %s and chara type %d and chara name %s", uuid, charaType, charaName)
	return nil
}

func (m *CharaDataManager) initCharaAvailable() {
	// todo 防止初始化的时候改变
	for _, commonDriver := range m.serverMap {
		charaSlice, _ := commonDriver.Core.List().Get(0)

		for _, val := range charaSlice {

			if charaInfo, ok := m.charaInfoMap[Chara(val)]; ok {
				charaInfo.BAvailable = true
			}

		}
	}

}

// 监听调用方与厂商服务丢失
func (m *CharaDataManager) initlistenNameLost() {
	m.dbusDaemon.InitSignalExt(m.signalLoop, true)
	m.signalLoop.Start()

	m.dbusDaemon.ConnectNameOwnerChanged(func(name string, oldOwner string, newOwner string) {

		if oldOwner == "" && newOwner != "" {
			return
		}

		m.actionMapMtx.Lock()
		defer m.actionMapMtx.Unlock()
		for _, val := range m.actionMap {
			codeStatusInfo := CodeStatusInfo{
				ActionId: val.ActionId,
				Sender:   val.UniqueSenderName,
			}
			// 发起方连接断开
			if val.UniqueSenderName == dbus.Sender(name) {
				codeStatusInfo.Msg = "Sender Disconnected"
				if val.ActionType == Eroll {

					if val.CharaType == AuthenticationFlagFace {
						codeStatusInfo.Code = StatusCode(FaceEnrollStatusCodeSenderDisconnected)
					} else {
						codeStatusInfo.Code = StatusCode(IrisEnrollSenderDisconnected)
					}

				} else {
					if val.CharaType == AuthenticationFlagFace {
						codeStatusInfo.Code = StatusCode(FaceVerifySenderDisconnected)
					} else {
						codeStatusInfo.Code = StatusCode(IrisVerifySenderDisconnected)
					}
				}
				logger.Debugf("the sender of action id %s disconnected", val.ActionId)
				val.codeStatusChan <- codeStatusInfo

			}
			// 接收方连接断开
			if val.UniqueReceivernName == dbus.Sender(name) {
				codeStatusInfo.Msg = "driver Disconnected"
				if val.ActionType == Eroll {
					if val.CharaType == AuthenticationFlagFace {
						codeStatusInfo.Code = StatusCode(FaceEnrollStatusCodeDisconnected)
					} else {
						codeStatusInfo.Code = StatusCode(IrisEnrollDisconnected)
					}

				} else {
					if val.CharaType == AuthenticationFlagFace {
						codeStatusInfo.Code = StatusCode(FaceVerifyDisconnected)
					} else {
						codeStatusInfo.Code = StatusCode(IrisVerifyDisconnected)
					}
				}
				logger.Debugf("the driver of action id %s disconnected", val.ActionId)
				val.codeStatusChan <- codeStatusInfo
			}

		}
	})

}
func (m *CharaDataManager) SaveCharaInfo(charaInfo *CharaInfo) error {
	m.charaInfoMtx.Lock()

	defer m.charaInfoMtx.Unlock()
	charaInfo.Time = time.Now().Unix()
	charaInfo.BAvailable = true
	m.charaInfoMap[charaInfo.Chara] = charaInfo
	// 删除磁盘中有同一用户、同一特征类型，同一名称但不可用特征，避免变为可用后，界面显示问题
	for key, val := range m.charaInfoMap {
		if val.Uuid == charaInfo.Uuid && val.CharaType == charaInfo.CharaType &&
			val.CharaName == charaInfo.CharaName && val.Chara != charaInfo.Chara && !val.BAvailable {
			delete(m.charaInfoMap, key)
		}
	}
	err := m.saveCharaInfoToFile()
	return err
}

func (m *CharaDataManager) saveCharaInfoToFile() error {

	data, err := json.MarshalIndent(m.charaInfoMap, "", "      ")
	if err != nil {
		logger.Warning(err)
		return err
	}
	os.MkdirAll(filepath.Dir(charaInfoFile), 0644)
	return ioutil.WriteFile(charaInfoFile, data, 0644)
}

func (m *CharaDataManager) GenActionId(sender dbus.Sender, driverName string, actionType ActionType, charaType CharaType, codeStatusInfochan chan CodeStatusInfo) (ActionId, error) {

	m.actionMapMtx.Lock()
	defer m.actionMapMtx.Unlock()
	key := string(sender) + " " + strconv.Itoa(int(charaType))

	_, ok := m.actionMap[key]

	if ok {
		err := fmt.Errorf("the action of the sender %s and chara type didn't is exist %d ", string(sender), charaType)
		logger.Warning(err)
		return "-1", err
	}
	actionId := utils.GenUuid()
	unionName, err := m.dbusDaemon.GetNameOwner(0, driverName)

	if err != nil {
		return "-1", err
	}
	m.actionMap[key] = &ActionInfo{
		UniqueSenderName:    sender,
		ReceiverName:        driverName,
		UniqueReceivernName: dbus.Sender(unionName),
		ActionType:          actionType,
		CharaType:           charaType,
		ActionId:            ActionId(actionId),
		codeStatusChan:      codeStatusInfochan,
		Code:                StatusCode(FaceEnrollInvalid),
	}
	logger.Debugf("GenActionId UniqueSenderName %s and UniqueReceivernName %s", sender, unionName)
	return ActionId(actionId), nil
}

func (m *CharaDataManager) ReleasseActionId(actionId ActionId) error {
	m.actionMapMtx.Lock()
	defer m.actionMapMtx.Unlock()
	for key, val := range m.actionMap {
		if val.ActionId == actionId {
			logger.Debugf("release action of id %s", actionId)
			close(val.codeStatusChan)
			delete(m.actionMap, key)
		}
	}

	return nil
}

func (m *CharaDataManager) GenChara() (Chara, error) {

	chara := utils.GenUuid()

	return Chara(chara), nil
}

func (m *CharaDataManager) CheckErollAvaliable(sender dbus.Sender, charaType CharaType, charaName string) error {

	m.actionMapMtx.RLock()
	defer m.actionMapMtx.RUnlock()
	var err error
	for _, val := range m.actionMap {
		if val.ActionType == Eroll && val.UniqueSenderName == sender {
			err = fmt.Errorf("sender is Erolling")
			return err
		}
	}

	uuid, err := m.GetUserUuidBySender(sender)
	if err != nil {
		logger.Warning(err)
		return err
	}

	if !m.CheckCharaNameAvailable(uuid, charaType, charaName) {
		err = fmt.Errorf("the two chara has same chara name of uuid %s and chara type %d", uuid, charaType)
		return err
	}

	return nil
}

func (m *CharaDataManager) CheckCharaNameAvailable(uuid UUID, charaType CharaType, charaName string) bool {

	m.charaInfoMtx.RLock()
	defer m.charaInfoMtx.RUnlock()

	for _, val := range m.charaInfoMap {
		if val.Uuid == uuid && val.CharaType == charaType && val.CharaName == charaName && val.BAvailable {
			return false
		}
	}

	return true
}
func (m *CharaDataManager) GetErollActionInfo(sender dbus.Sender) *ActionInfo {

	m.actionMapMtx.RLock()
	defer m.actionMapMtx.RUnlock()
	for _, val := range m.actionMap {
		if val.ActionType == Eroll && val.UniqueSenderName == sender {
			return val
		}
	}

	return nil
}

func (m *CharaDataManager) GetDriverInfo() string {

	logger.Debug("GetDriverInfo")
	m.serverMtx.RLock()
	defer m.serverMtx.RUnlock()

	var driverInfoList []DriverInfo

	for serverName, driver := range m.serverMap {
		info := DriverInfo{DriverName: serverName, CharaType: driver.DriverCharaType}
		driverInfoList = append(driverInfoList, info)
	}
	logger.Debug(driverInfoList)
	if len(driverInfoList) == 0 {
		return ""
	}
	driverInfo, err := json.Marshal(driverInfoList)
	if err != nil {
		logger.Warning(err)
		return ""
	}
	return string(driverInfo)
}

func (m *CharaDataManager) GetActionInfo(actionId ActionId) *ActionInfo {
	m.actionMapMtx.RLock()
	defer m.actionMapMtx.RUnlock()
	for _, val := range m.actionMap {
		if val.ActionId == actionId {

			return val

		}
	}

	return nil
}

func (m *CharaDataManager) ChangeCharaName(uuid UUID, charaType CharaType, oldName, newName string) error {

	m.charaInfoMtx.Lock()
	defer m.charaInfoMtx.Unlock()
	var charaInfo *CharaInfo
	for _, val := range m.charaInfoMap {

		if val.Uuid == uuid && val.CharaType == charaType && val.CharaName == newName && val.BAvailable {
			return fmt.Errorf("the new name of %s had another chara ", newName)
		}
		if val.Uuid == uuid && val.CharaType == charaType && val.CharaName == oldName && val.BAvailable {
			charaInfo = val
			charaInfo.CharaName = newName
		}
	}
	if charaInfo == nil {
		return fmt.Errorf("not found chara info by uuid=%s,chara type=%d,name=%s", uuid, charaType, oldName)
	}
	// 删除磁盘中有同一用户、同一特征类型，同一名称但不可用特征，避免变为可用后，界面显示问题
	for key, val := range m.charaInfoMap {
		if val.CharaName == oldName && val.Uuid == uuid && val.CharaType == charaType && !val.BAvailable && charaInfo.Chara != val.Chara {
			logger.Debugf("delete uuid is %s,chara type is %d and chara name is %s，but not available", uuid, charaType, val.CharaName)
			delete(m.charaInfoMap, key)
		}
	}

	m.saveCharaInfoToFile()

	return nil
}

func (m *CharaDataManager) DeleteChara(uuid UUID, charaType CharaType, charaName string) error {

	m.charaInfoMtx.Lock()
	defer m.charaInfoMtx.Unlock()
	var charaInfo CharaInfo
	for _, val := range m.charaInfoMap {
		if val.Uuid == uuid && val.CharaType == charaType && val.CharaName == charaName {
			charaInfo = *val
			break
		}
	}

	logger.Debugf("delete chara by uuid %s and chara type %d and chara name %s", uuid, charaType, charaName)
	delete(m.charaInfoMap, charaInfo.Chara)

	m.saveCharaInfoToFile()

	return nil
}

func (m *CharaDataManager) GetAvailableCharaInfoByDriverNameAndType(uuid UUID, charaType CharaType, driverName string) []CharaInfo {

	m.charaInfoMtx.Lock()
	defer m.charaInfoMtx.Unlock()
	var charaInfo []CharaInfo
	driver, _ := m.GetDriver(driverName, charaType)
	if driver == nil || driver.DriverCharaType&charaType == 0 {
		return charaInfo
	}

	for _, val := range m.charaInfoMap {
		if val.Uuid == uuid && val.CharaType == charaType && val.ServerName == driverName && val.BAvailable {
			charaInfo = append(charaInfo, *val)
		}
	}

	return charaInfo
}

func (m *CharaDataManager) handleDriverSignalEnrollStatus(actionId ActionId, code int32, msg string) {

	m.actionMapMtx.Lock()
	defer m.actionMapMtx.Unlock()
	for _, actionInfo := range m.actionMap {
		if actionInfo.ActionId == actionId {

			actionInfo.codeStatusChan <- CodeStatusInfo{
				ActionId: actionId,
				Sender:   actionInfo.UniqueSenderName,
				Code:     StatusCode(code),
				Msg:      msg,
			}
			logger.Debugf("recive enroll status action id %s,code %d and msg %s", actionId, code, msg)
			actionInfo.Code = StatusCode(code)

		}
	}

}
func (m *CharaDataManager) handleDriverSignalVerifyStatus(actionId ActionId, code int32, msg string) {
	m.actionMapMtx.Lock()
	defer m.actionMapMtx.Unlock()
	for _, actionInfo := range m.actionMap {
		if actionInfo.ActionId == actionId {

			actionInfo.codeStatusChan <- CodeStatusInfo{
				ActionId: actionId,
				Sender:   actionInfo.UniqueSenderName,
				Code:     StatusCode(code),
				Msg:      msg,
			}
			logger.Debugf("recive verify status action id %s,code %d and msg %s", actionId, code, msg)
			actionInfo.Code = StatusCode(code)

		}
	}
}

func (m *CharaDataManager) HandleDriverCharaTypeChange(serverName string, oldcharaType CharaType, newcharaType CharaType) {
	// 不需要更新可用的特征值，依赖List变化进行更新

	logger.Debugf("HandleDriverCharaTypeChange sever name %s, old chara type %d and new chara type %d",
		serverName, oldcharaType, newcharaType)
	// 厂商服务下设备可用状态变化，需要通知控制中心
	driver := m.serverMap[serverName]
	// 增加的chara type
	charaAdd := oldcharaType | newcharaType ^ oldcharaType

	// 减少的chara type
	charaDelete := oldcharaType&newcharaType ^ oldcharaType

	// 可能会跟list变化重复
	if charaAdd != 0 {
		chara, err := driver.Core.List().Get(0)

		if err != nil {
			logger.Warning(err)
		}

		m.charaInfoMtx.Lock()
		defer m.charaInfoMtx.Unlock()
		logger.Debug("handleDriverListChange")

		tempCharaInfoMap := make(map[Chara]bool, 5)
		// 方便查找
		for _, val := range chara {

			tempCharaInfoMap[Chara(val)] = true
		}

		for chara, charaInfo := range m.charaInfoMap {
			// 对该服务进行全部匹配判断
			if charaInfo.ServerName == serverName {

				_, ok := tempCharaInfoMap[chara]

				if ok {
					// 本地有，厂商有（特征值）
					charaInfo.BAvailable = true

				} else {
					// 本地有，厂商没有（特征值）

					charaInfo.BAvailable = false

				}
			}
		}
	}

	if charaDelete != 0 {
		m.actionMapMtx.RLock()
		defer m.actionMapMtx.RUnlock()
		for _, actionInfo := range m.actionMap {
			if actionInfo.UniqueReceivernName == driver.UniqueName && actionInfo.CharaType&charaDelete != 0 {
				codeStatusInfo := CodeStatusInfo{
					ActionId: actionInfo.ActionId,
					Sender:   actionInfo.UniqueSenderName,
					Msg:      "chara not support",
				}
				if actionInfo.ActionType == Eroll {
					if actionInfo.CharaType == AuthenticationFlagFace {
						codeStatusInfo.Code = StatusCode(FaceEnrollStatusCodeDisconnected)
					} else {
						codeStatusInfo.Code = StatusCode(IrisEnrollDisconnected)
					}
					codeStatusInfo.Code = StatusCode(FaceEnrollStatusCodeDisconnected)
				} else {
					codeStatusInfo.Code = StatusCode(FaceVerifyDisconnected)
				}

				for chara, charaInfo := range m.charaInfoMap {
					if charaInfo.ServerName == serverName && charaInfo.CharaType&charaDelete != 0 {
						m.charaInfoMap[chara].BAvailable = false
					}
				}
				logger.Debugf("the device not found of action id %s disconnected", actionInfo.ActionId)
				actionInfo.codeStatusChan <- codeStatusInfo
			}
		}
	}

	m.driverInfoChan <- DriverInfo{
		DriverName: serverName,
		CharaType:  m.serverMap[serverName].DriverCharaType,
	}
}

func (m *CharaDataManager) handleDriverListChange(serverName string, chara []Chara) {
	m.charaInfoMtx.Lock()
	defer m.charaInfoMtx.Unlock()
	logger.Debug("handleDriverListChange")

	tempCharaInfoMap := make(map[Chara]bool, 5)
	// 方便查找
	for _, val := range chara {
		tempCharaInfoMap[val] = true
	}

	for chara, charaInfo := range m.charaInfoMap {
		// 对该服务进行全部匹配判断
		if charaInfo.ServerName == serverName {

			_, ok := tempCharaInfoMap[chara]

			if ok {
				// 本地有，厂商有（特征值）
				charaInfo.BAvailable = true

			} else {
				// 本地有，厂商没有（特征值）

				charaInfo.BAvailable = false

			}
		}
	}
	// 需要发送的
	var charaType = m.serverMap[serverName].DriverCharaType
	if charaType&AuthenticationFlagFace != 0 {
		m.charaInfoChan <- CharaInfo{
			ServerName: serverName,
			CharaType:  AuthenticationFlagFace,
		}
	}

	if charaType&AuthenticationFlagIris != 0 {
		m.charaInfoChan <- CharaInfo{
			ServerName: serverName,
			CharaType:  AuthenticationFlagIris,
		}
	}
}
