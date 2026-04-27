package charaDataManger

import (
	"fmt"

	"github.com/godbus/dbus"
	accounts "github.com/linuxdeepin/go-dbus-factory/com.deepin.daemon.accounts"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

func (m *CharaDataManager) GetUserUuidBySender(sender dbus.Sender) (UUID, error) {

	uid, err := m.service.GetConnUID(string(sender))
	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}
	newAccounts := accounts.NewAccounts(m.service.Conn())

	userPath, err := newAccounts.FindUserById(0, fmt.Sprint(uid))

	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}

	userObj, err := accounts.NewUser(m.service.Conn(), dbus.ObjectPath(userPath))
	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}

	uuid, err := userObj.UUID().Get(0)
	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}
	if uuid == "" {
		err = fmt.Errorf("sender %q uuid is empty", sender)
		logger.Warning(err)
		return UUID("-1"), err
	}

	return UUID(uuid), nil

}

func (m *CharaDataManager) GetUserUuidByUserName(userName string) (UUID, error) {

	newAccounts := accounts.NewAccounts(m.service.Conn())

	userPath, err := newAccounts.FindUserByName(0, userName)

	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}

	userObj, err := accounts.NewUser(m.service.Conn(), dbus.ObjectPath(userPath))
	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}

	uuid, err := userObj.UUID().Get(0)
	if err != nil {
		logger.Warning(err)
		return UUID("-1"), err
	}
	if uuid == "" {
		err = fmt.Errorf("user %q uuid is empty", userName)
		logger.Warning(err)
		return UUID("-1"), err
	}

	return UUID(uuid), nil

}
