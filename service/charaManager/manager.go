package charaManager

import (
	"fmt"
	"sync"

	ofdbus "github.com/linuxdeepin/go-dbus-factory/org.freedesktop.dbus"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	. "pkg.deepin.io/dde/authentication/service/charaDataManger"
	"github.com/linuxdeepin/go-lib/dbusutil"
)

const (
	dBusCharaMangerPath = "/com/deepin/daemon/Authenticate/CharaManger"
	dBusCharaMangerface = "com.deepin.daemon.Authenticate.CharaManger"
	charaInfoFile       = "/usr/share/deepin-authentication/chara/charaInfo"

	actionIdFaceEnroll = "com.deepin.daemon.authenticate.Face.enroll"
	actionIdFaceDelete = "com.deepin.daemon.authenticate.Face.delete-enrolled-face"
	actionIdFaceRename = "com.deepin.daemon.authenticate.Face.rename-enrolled-face"

	actionIdIrisEnroll = "com.deepin.daemon.authenticate.Iris.enroll"
	actionIdIrisDelete = "com.deepin.daemon.authenticate.Iris.delete-enrolled-iris"
	actionIdIrisRename = "com.deepin.daemon.authenticate.Iris.rename-enrolled-iris"
)

type CharaInfoDbusWarp struct {
	CharaName string    `json:"CharaName"`
	CharaType CharaType `json:"CharaType"`
	Time      int64     `json:"Time"`
}

//go:generate dbusutil-gen -type Manager manager.go
//go:generate dbusutil-gen em -type Manager
type Manager struct {
	PropsMu    sync.RWMutex
	service    *dbusutil.Service
	sysSigLoop *dbusutil.SignalLoop
	dbusDaemon ofdbus.DBus
	sigLoop    *dbusutil.SignalLoop
	// 可能有多个控制中心在同时录入
	codeChanMap map[ActionId]chan CodeStatusInfo
	// driver 发生变化时通过该channel传递上来
	driverInfoChan chan DriverInfo
	// 存放厂商服务信息
	DriverInfo string

	charaInfoChan chan CharaInfo
	charaData     *CharaDataManager

	signals *struct {
		// 录入过程中的消息
		EnrollStatus struct {
			Sender string           // 该消息的接收者在 dbus 上的唯一名称
			Code   EnrollStatusCode // 录入过程状态码
			Msg    string           // json: EnrollMessage
		}

		// 提醒控制中心某类的生物特征数据发生了变化, 应该重新调用 List 函数的信号.
		// 控制中心这里调用 List 的时候实际上列表内容不一定会发生变化, 因为有可能更新的是其他用户的特征数据.
		CharaUpdated struct {
			DriverName string
			CharaType  CharaType
		}

		// 通知控制中心driver发生变化，主要是规避控制中心不能很好的监听属性
		DriverChanged struct {
		}
	}
}

func newManager(service *dbusutil.Service) *Manager {
	sysBus := service.Conn()

	m := &Manager{
		service:        service,
		sysSigLoop:     dbusutil.NewSignalLoop(sysBus, 10),
		sigLoop:        dbusutil.NewSignalLoop(service.Conn(), 10),
		dbusDaemon:     ofdbus.NewDBus(service.Conn()),
		driverInfoChan: make(chan DriverInfo, 5),
		charaInfoChan:  make(chan CharaInfo, 5),
		codeChanMap:    make(map[ActionId]chan CodeStatusInfo),
	}
	return m
}
func (m *Manager) GetInterfaceName() string {
	return dBusCharaMangerface
}
func (m *Manager) init() {

	m.charaData = GetCharaCommonDataManger()
	m.PropsMu.Lock()
	m.DriverInfo = m.charaData.GetDriverInfo()
	m.PropsMu.Unlock()
	m.charaData.SetCharaAndDriverInfoChan(m.charaInfoChan, m.driverInfoChan)
	go m.listenDriverInfo()
	go m.listenCharaInfo()
}

func (m *Manager) saveCharaInfoToActionInfo(actionId ActionId, chara Chara, charaName string) error {
	actionInfo := m.charaData.GetActionInfo(actionId)

	if actionInfo == nil {
		err := fmt.Errorf("save chara info to actionInfo fial,no found action info by action id %s", actionId)
		loggerCharaManger.Warning(err)
		return err
	}
	uuid, err := m.charaData.GetUserUuidBySender(actionInfo.UniqueSenderName)
	if err != nil {
		return err
	}

	actionInfo.CharaInfo = CharaInfo{
		ServerName: actionInfo.ReceiverName,
		Uuid:       uuid,
		CharaType:  actionInfo.CharaType,
		CharaName:  charaName,
		Chara:      chara,
		BAvailable: false,
	}

	return nil
}

// 从actionInfo中把相应的特征信息存入磁盘
func (m *Manager) saveCharaInfoToCharaData(actionId ActionId) error {
	actionInfo := m.charaData.GetActionInfo(actionId)

	if actionInfo == nil {
		err := fmt.Errorf("save chara info to actionInfo fial,no found action info by action id %s", actionId)
		loggerCharaManger.Warning(err)
		return err
	}
	err := m.charaData.SaveCharaInfo(&actionInfo.CharaInfo)
	return err
}

func (m *Manager) listenStatusInfo(actionId ActionId) {
	codeChan := m.codeChanMap[actionId]

loop:
	for {
		select {
		case result, ok := <-codeChan:

			if !ok {

				break loop
			}

			actionInfo := m.charaData.GetActionInfo(result.ActionId)

			if actionInfo != nil {
				if actionInfo.CharaType == AuthenticationFlagFace &&
					result.Code == StatusCode(FaceVerifySenderDisconnected) {
					driver, _ := m.charaData.GetDriver(actionInfo.ReceiverName, actionInfo.CharaType)
					if driver != nil {
						driver.Core.EnrollStop(0, string(actionInfo.ActionId))
					}
					m.releasseActionInfo(result.ActionId)
					break loop

				} else if actionInfo.CharaType == AuthenticationFlagIris &&
					result.Code == StatusCode(IrisEnrollSenderDisconnected) {
					driver, _ := m.charaData.GetDriver(actionInfo.ReceiverName, actionInfo.CharaType)
					if driver != nil {
						driver.Core.EnrollStop(0, string(actionInfo.ActionId))
					}
					m.releasseActionInfo(result.ActionId)

					break loop
				} else {
					if (actionInfo.CharaType == AuthenticationFlagFace && result.Code == StatusCode(FaceEnrollStatusCodeDisconnected)) ||
						(actionInfo.CharaType == AuthenticationFlagIris && result.Code == StatusCode(IrisEnrollDisconnected)) {
						m.releasseActionInfo(result.ActionId)
					}
					loggerCharaManger.Debugf("EnrollStatus sender %s, code %d and msg %s", result.Sender, result.Code, result.Msg)
					err := m.service.Emit(m, "EnrollStatus", result.Sender, result.Code, result.Msg)
					if err != nil {
						loggerCharaManger.Warning(err)
					}
				}

			} else {
				loggerCharaManger.Debugf("close listenStatusInfo of %s ActionId", actionId)
				break loop
			}

		}
	}
}

func (m *Manager) releasseActionInfo(actionId ActionId) {

	m.charaData.ReleasseActionId(actionId)
	delete(m.codeChanMap, actionId)
}

func (m *Manager) listenDriverInfo() {

	for {
		select {
		case _, ok := <-m.driverInfoChan:

			if !ok {
				loggerCharaManger.Debug("not ok")
				continue
			}
			m.PropsMu.Lock()
			m.DriverInfo = m.charaData.GetDriverInfo()
			m.PropsMu.Unlock()
			err := m.service.Emit(m, "DriverChanged")
			if err != nil {
				loggerCharaManger.Warning(err)
			}

		}
	}
}

func (m *Manager) listenCharaInfo() {

	for {
		select {
		case result := <-m.charaInfoChan:
			loggerCharaManger.Debugf("emit CharaUpdated server name %s and chara type %d", result.ServerName, result.CharaType)
			err := m.service.Emit(m, "CharaUpdated", result.ServerName, result.CharaType)
			if err != nil {
				loggerCharaManger.Warning(err)
			}
		}
	}
}

func (m *Manager) getCheckPasswdActionId(action string, charaType CharaType) (string, error) {
	switch action {
	case "enroll":
		if charaType&AuthenticationFlagFace != 0 {
			return actionIdFaceEnroll, nil

		} else if charaType&AuthenticationFlagIris != 0 {
			return actionIdIrisEnroll, nil
		}

	case "delete":
		if charaType&AuthenticationFlagFace != 0 {
			return actionIdFaceDelete, nil

		} else if charaType&AuthenticationFlagIris != 0 {
			return actionIdIrisDelete, nil
		}

	case "rename":
		if charaType&AuthenticationFlagFace != 0 {
			return actionIdFaceRename, nil

		} else if charaType&AuthenticationFlagIris != 0 {
			return actionIdIrisRename, nil
		}
	}

	return "", fmt.Errorf("not found check passwd action by action %s and chara type %d", action, charaType)
}
