package charaManager

import (
	"encoding/json"
	"fmt"

	"github.com/godbus/dbus"
	"github.com/LingmoOS/velora-api/polkit"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
)

func (m *Manager) EnrollStart(sender dbus.Sender, driverName string, charaType CharaType, charaName string) (dbus.UnixFD, *dbus.Error) {

	loggerCharaManger.Debugf("EnrollStart sender %s,driver name %s,chara type %d and chara name %s", sender, driverName, charaType, charaName)
	// 1 、开启密码鉴权
	passwdCheckActionId, err := m.getCheckPasswdActionId("enroll", charaType)
	if err != nil {
		loggerCharaManger.Warning(err)
		return -1, dbusutil.ToError(err)
	}
	err = polkit.CheckAuth(passwdCheckActionId, string(sender), polkit.NewPolKitAuthDetails(AuthenticationFlagPassword))
	if err != nil {
		loggerCharaManger.Warning(err)
		return -1, dbusutil.ToError(err)
	}

	// 2、检查录入是否存在
	err = m.charaData.CheckErollAvaliable(sender, charaType, charaName)
	if err != nil {
		loggerCharaManger.Warning(err)
		return -1, dbusutil.ToError(err)
	}
	// 3、获取厂商服务
	driver, claim := m.charaData.GetDriver(driverName, charaType)
	if driver == nil || claim {
		err = fmt.Errorf("not found driver by server name %s and chara Type %d or driver claim %t", driverName, charaType, claim)
		loggerCharaManger.Warning(err)
		return -1, dbusutil.ToError(err)
	}
	loggerCharaManger.Debugf("claim %t", claim)
	// 4、生成特征值
	chara, err := m.charaData.GenChara()

	if err != nil {
		return -1, dbusutil.ToError(err)
	}
	// 5、生成action info
	ch := make(chan CodeStatusInfo, 5)
	actionId, err := m.charaData.GenActionId(sender, driverName, Eroll, charaType, ch)
	if err != nil {
		loggerCharaManger.Warning(err)
		return -1, dbusutil.ToError(err)
	}
	m.codeChanMap[actionId] = ch

	// 6、开启录入
	loggerCharaManger.Debug("EnrollStart")
	uniFd, err := driver.Core.EnrollStart(0, string(chara), int32(charaType), string(actionId))

	if err != nil {
		loggerCharaManger.Warning(err)
		m.charaData.ReleasseActionId(actionId)
		return -1, dbusutil.ToError(err)
	}
	// 7、暂存特征信息到action info
	err = m.saveCharaInfoToActionInfo(actionId, chara, charaName)
	if err != nil {
		loggerCharaManger.Error(err)

		driver.Core.EnrollStop(0, string(actionId))
		m.releasseActionInfo(actionId)
		return -1, dbusutil.ToError(err)
	}

	go m.listenStatusInfo(actionId)
	return uniFd, nil

}

func (m *Manager) EnrollStop(sender dbus.Sender) (busErr *dbus.Error) {
	loggerCharaManger.Debugf("EnrollStop sender %s", sender)
	actionInfo := m.charaData.GetErollActionInfo(sender)
	var err error
	if actionInfo == nil {
		err = fmt.Errorf("not found information by %s sender", sender)
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}
	driver, _ := m.charaData.GetDriver(actionInfo.ReceiverName, actionInfo.CharaType)
	if driver == nil {
		err = fmt.Errorf("not found driver by server name %s and charaType %d", actionInfo.ReceiverName, actionInfo.CharaType)
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}

	err = driver.Core.EnrollStop(0, string(actionInfo.ActionId))
	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}
	if (actionInfo.CharaType == AuthenticationFlagFace && actionInfo.Code == StatusCode(FaceEnrollSuccess)) ||
		(actionInfo.CharaType == AuthenticationFlagIris && actionInfo.Code == StatusCode(FaceEnrollSuccess)) {

		loggerCharaManger.Warning("saveCharaInfoToCharaData")
		m.saveCharaInfoToCharaData(actionInfo.ActionId)
	}
	// todo 虹膜
	m.releasseActionInfo(actionInfo.ActionId)
	return nil
}

func (m *Manager) Rename(sender dbus.Sender, charaType CharaType, oldName, newName string) (busErr *dbus.Error) {

	loggerCharaManger.Debugf("Rename sender %s,chara type %d old name %sand new name %s", sender, charaType, oldName, newName)
	// 1 、开启密码鉴权

	passwdCheckActionId, err := m.getCheckPasswdActionId("rename", charaType)
	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}
	err = polkit.CheckAuth(passwdCheckActionId, string(sender), polkit.NewPolKitAuthDetails(AuthenticationFlagPassword))
	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}
	uuid, err := m.charaData.GetUserUuidBySender(sender)

	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}

	err = m.charaData.ChangeCharaName(uuid, charaType, oldName, newName)

	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}

	return nil
}

func (m *Manager) Delete(sender dbus.Sender, charaType CharaType, charaName string) (busErr *dbus.Error) {

	loggerCharaManger.Debugf("Delete sender %s,chara type %d and chara name %s", sender, charaType, charaName)
	var err error
	// 1 、开启密码鉴权
	passwdCheckActionId, err := m.getCheckPasswdActionId("delete", charaType)
	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}
	err = polkit.CheckAuth(passwdCheckActionId, string(sender), polkit.NewPolKitAuthDetails(AuthenticationFlagPassword))
	if err != nil {
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}

	charaInfo := m.charaData.GetCharaInfo(sender, charaType, charaName)

	if charaInfo == nil {
		err = fmt.Errorf("not found chara info  by sender %s and chara type %d and chara name %s", sender, charaType, charaName)
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}

	driver, claim := m.charaData.GetDriver(charaInfo.ServerName, charaType)
	if driver == nil || claim {
		err = fmt.Errorf("not found driver by server name %s and charaType %d or driver claim %t", charaInfo.ServerName, charaInfo.CharaType, claim)
		loggerCharaManger.Warning(err)
		return dbusutil.ToError(err)
	}

	err = driver.Core.Delete(0, string(charaInfo.Chara))

	if err != nil {
		return dbusutil.ToError(err)
	}

	m.charaData.DeleteChara(charaInfo.Uuid, charaInfo.CharaType, charaInfo.CharaName)

	return nil
}

func (m *Manager) List(sender dbus.Sender, driverName string, charaType CharaType) (string, *dbus.Error) {

	loggerCharaManger.Debugf("List sender %s,driver name %s and chara type %d", sender, driverName, charaType)
	uuid, err := m.charaData.GetUserUuidBySender(sender)

	if err != nil {
		loggerCharaManger.Warning(err)
		return "", dbusutil.ToError(err)
	}

	charaInfo := m.charaData.GetAvailableCharaInfoByDriverNameAndType(uuid, charaType, driverName)

	if len(charaInfo) == 0 {
		return "", nil
	}
	var charaInfoDbusWarp []CharaInfoDbusWarp

	for _, val := range charaInfo {
		charaInfoDbusWarp = append(charaInfoDbusWarp, CharaInfoDbusWarp{
			CharaName: val.CharaName,
			CharaType: val.CharaType,
			Time:      val.Time,
		})
	}
	charaTempInfo, err := json.Marshal(charaInfoDbusWarp)
	if err != nil {
		loggerCharaManger.Warning(err)
		return "err", dbusutil.ToError(err)
	}
	return string(charaTempInfo), nil

}
