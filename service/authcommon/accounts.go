package authcommon

import (
	"errors"
	"fmt"

	login1 "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.login1"

	"github.com/godbus/dbus"
	accounts "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.accounts"
)

type UserInfo struct {
	Name        string
	Uuid        string
	SessionPath string
	HomeDir     string
}

var _bus *dbus.Conn

func init() {
	var err error
	_bus, err = dbus.SystemBus()
	if err != nil {
		logger.Warning(err)
	}
}

func GetUserInfo(user string) (*UserInfo, error) {
	var userInfo UserInfo
	if user == "" {
		return nil, errors.New("empty user")
	}

	if _bus == nil {
		return nil, errors.New("can not create system bus")
	}
	newAccounts := accounts.NewAccounts(_bus)
	userPath, err := newAccounts.FindUserByName(0, user)

	if err != nil {
		return nil, err
	}

	userObj, err := accounts.NewUser(_bus, dbus.ObjectPath(userPath))
	if err != nil {
		return nil, err
	}

	uuid, err := userObj.UUID().Get(0)
	if err != nil {
		return nil, err
	}
	if uuid == "" {
		err = fmt.Errorf("user %q uuid is empty", user)
		return nil, err
	}
	homeDir, err := userObj.HomeDir().Get(0)
	if err != nil {
		return nil, err
	}

	userInfo.Name = user
	userInfo.Uuid = uuid

	path, err := getGUIUserSessionPath(user)
	if err != nil {
		userInfo.SessionPath = ""
	} else {
		userInfo.SessionPath = path
	}

	userInfo.HomeDir = homeDir

	return &userInfo, nil
}

func getGUIUserSessionPath(username string) (string, error) {
	if username == "" {
		return "", errors.New("empty user")
	}

	if _bus == nil {
		return "", errors.New("can not create system bus")
	}

	loginManager := login1.NewManager(_bus)
	listSessions, err := loginManager.ListSessions(0)
	if err != nil {
		return "", err
	}

	var sessionPath string
	for _, session := range listSessions {
		if session.UserName == username {
			if IsGUISession(session.Path) {
				sessionPath = string(session.Path)
				break
			}
		}
	}
	if sessionPath == "" {
		return "", fmt.Errorf("can not find GUI session path")
	}
	return sessionPath, nil
}

func IsGUISession(path dbus.ObjectPath) bool {
	if _bus == nil {
		return false
	}

	session, err := login1.NewSession(_bus, path)
	if err != nil {
		return false
	}

	value, err := session.TTY().Get(0)
	if err != nil {
		return false
	}

	return value == ""
}

func GetUsernameBySessionPath(path dbus.ObjectPath) string {
	if _bus == nil {
		return ""
	}

	session, err := login1.NewSession(_bus, path)
	if err != nil {
		return ""
	}

	name, err := session.Name().Get(0)
	if err != nil {
		return ""
	}

	return name
}

func GetUserNameByUuid(uuid string) (string, error) {
	if _bus == nil {
		return "", errors.New("can not create system bus")
	}

	newAccounts := accounts.NewAccounts(_bus)
	userList, err := newAccounts.UserList().Get(0)
	if err != nil {
		return "", errors.New("can not get userList")
	}

	for _, userPath := range userList {
		user, err := accounts.NewUser(_bus, dbus.ObjectPath(userPath))
		if err != nil {
			continue
		}

		userUuid, err := user.UUID().Get(0)
		if err != nil {
			continue
		}

		if userUuid == uuid {
			username, err := user.UserName().Get(0)
			if err != nil {
				return "", fmt.Errorf("can not get target username: %s", err)
			}
			return username, nil
		}
	}
	return "", fmt.Errorf("can not found username for %s", uuid)
}
