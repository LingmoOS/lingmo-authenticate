package authenticate

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	login1 "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.login1"

	"github.com/godbus/dbus"
	accounts "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.accounts"
	ofdbus "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.dbus"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/procfs"
	"pkg.deepin.io/dde/authentication/pkg/common"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	"pkg.deepin.io/dde/authentication/service/authenticate/session"
	"pkg.deepin.io/dde/authentication/service/encrypt"
	"pkg.deepin.io/dde/authentication/service/task"
)

//go:generate dbusutil-gen em -type Manager

const (
	dbusServicePath       = "/com/deepin/daemon/Authenticate"
	dbusServiceInterface  = "com.lingmo.daemon.Authenticate"
	pamCommonAuthFilePath = "/etc/pam.d/common-auth"
	deepinPamConfFilePath = "/etc/pam.d/deepin_pam_unix"
)

const (
	frameworkStatusOk          = 1
	frameworkStatusPamAbnormal = 2
)

type oneKeyLoginResult struct {
	gid      string
	txType   string
	flag     int
	username string
	result   bool
}

type Manager struct {
	nextId   uint
	nextIdMu sync.Mutex

	crypts     []encrypt.AsymCrypt
	service    *dbusutil.Service
	sysSigLoop *dbusutil.SignalLoop
	dbusDaemon ofdbus.DBus

	limits       map[LimitType]map[string]map[string]*limit
	limitsMu     sync.RWMutex
	saveLimitsMu sync.Mutex
	config       Config
	exitCbMap    map[string]func()
	exitCbMu     sync.Mutex

	SupportedFlags int32
	//todo: 支持的加密方式
	SupportEncrypts string
	//todo: 框架是否正常可用
	FrameworkState int32

	oneKeyLoginRes    oneKeyLoginResult
	oneKeyLoginWaitCh chan oneKeyLoginResult
	privileges        *privilegesManager

	fsWatcher *fsnotify.Watcher

	// nolint
	signals *struct {
		LimitUpdated struct {
			username string
		}
	}
}

func FrameworkStatus() int32 {
	_, err := os.Stat(pamCommonAuthFilePath)
	if err != nil && os.IsNotExist(err) {
		return frameworkStatusPamAbnormal
	}

	_, err = os.Stat(deepinPamConfFilePath)
	if err != nil && os.IsNotExist(err) {
		return frameworkStatusPamAbnormal
	}

	lines, err := ReadFileLines(pamCommonAuthFilePath)
	if err != nil {
		return frameworkStatusPamAbnormal
	}

	// simple check
	for _, line := range lines {
		line = strings.Trim(line, " ")
		if len(line) != 0 && line[0] != '#' {
			if strings.Contains(line, "pam_deepin_authentication.so") {
				return frameworkStatusOk
			} else {
				if canSkipFramework(line) {
					return frameworkStatusPamAbnormal
				}
			}
		}
	}

	return frameworkStatusPamAbnormal
}

func canSkipFramework(line string) bool {
	begin := strings.Index(line, "[")
	if begin < 0 {
		return false
	}

	end := strings.Index(line, "]")
	if end < 0 {
		return false
	}

	if begin > end {
		return false
	}

	controlFlags := line[begin+1 : end]

	pamFlags := strings.Fields(controlFlags)

	var bSuccessSkip, bFailSkip bool

	for _, flag := range pamFlags {
		options := strings.Split(flag, "=")

		if len(options) == 2 {
			if options[0] == "success" && options[1] == "done" {
				bSuccessSkip = true
			}

			if options[0] == "auth_err" && (options[1] == "die" || options[1] == "done") {
				bFailSkip = true
			}
		}
	}

	if bSuccessSkip && bFailSkip {
		return true
	}

	return false
}

func (m *Manager) emitSignalLimitUpdated(username string) {
	logger.Debugf("emit signal LimitUpdated username: %s", username)
	err := m.service.Emit(m, "LimitUpdated", username)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) genId() string {
	m.nextIdMu.Lock()
	defer m.nextIdMu.Unlock()

	id := strconv.FormatUint(uint64(m.nextId), 10)
	m.nextId++
	return id
}

func (m *Manager) GetInterfaceName() string {
	return dbusServiceInterface
}

func newManage(service *dbusutil.Service) (*Manager, error) {
	systemConn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}

	crypt := make([]encrypt.AsymCrypt, len(encrypt.AlgTypes))
	for _, i := range encrypt.AlgTypes {
		crypt[i], _ = createCrypt(i)
		logger.Debugf("create crypt type:%d, flags: %v", i, encrypt.AlgTypes)
	}

	m := &Manager{
		crypts:     crypt,
		service:    service,
		dbusDaemon: ofdbus.NewDBus(systemConn),
		sysSigLoop: dbusutil.NewSignalLoop(systemConn, 10),
		nextId:     1,
		SupportedFlags: AuthenticationFlagPassword | AuthenticationFlagFingerprint | AuthenticationFlagUKey |
			AuthenticationFlagFace | AuthenticationFlagIris | AuthenticationFlagCustom,
		FrameworkState: FrameworkStatus(),
		privileges:     newPrivilegesManager(),
		exitCbMap:      make(map[string]func()),
	}
	return m, nil
}

func (m *Manager) listenTTYFileChanged() {
	var err error
	m.fsWatcher, err = fsnotify.NewWatcher()
	if err != nil {
		logger.Warning(err)
		return
	}

	go func() {
		if m.fsWatcher != nil {
			err = m.fsWatcher.Add("/sys/devices/virtual/tty/tty0/active")
			if err != nil {
				logger.Warning(err)
				return
			}
			m.listenTTYChanged()
		}
	}()
}

func (m *Manager) listenDBusSignalNameLost() {
	dBus := ofdbus.NewDBus(m.service.Conn())
	dBus.InitSignalExt(m.sysSigLoop, true)

	_, err := dBus.ConnectNameLost(func(name string) {
		task.GetTaskManager().DoSignalTask("NameLost", name)
	})
	if err != nil {
		logger.Warning(err)
	}
}

// 接收到系统的信号之后,调用已经注册的回调函数，结束已经开启但还未完成的认证.
func (m *Manager) listenOSSignals() {
	sigs := make(chan os.Signal, 1)

	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigs
		logger.Infof("receive signal: %v, start exec callback", sig)

		for _, fn := range m.exitCbMap {
			fn()
		}

		logger.Info("end exec callback")
		os.Exit(-1)
	}()
}

func (m *Manager) init() {
	err := loadConfig(configFile, &m.config)
	if err != nil && !os.IsNotExist(err) {
		logger.Warning(err)
	}
	m.sysSigLoop.Start()
	m.initLimits()

	m.listenLoginSignalSessionNew()
	m.listenOSSignals()
	m.listenTTYFileChanged()
	m.listenDBusSignalNameLost()
}

func (m *Manager) Authenticate(sender dbus.Sender, username string, authFlags, appType int32) (result string, busErr *dbus.Error) {
	if username == "" {
		return "", dbusutil.ToError(errors.New("argument username is empty"))
	}
	if !IsSupportedType(int(appType)) {
		return "", dbusutil.ToError(fmt.Errorf("appType %d is not support", appType))
	}
	id := m.genId()
	logger.Debugf("Authenticate sender: %s, username: %q, authFlags: %d, appType: %d, id: %s",
		sender, username, authFlags, appType, id)

	limitType := m.GetLimitType(sender)

	m.initLimitsByUsername(limitType, username)

	// 开启一个新的session,在该session中进行具体的认证,认证结果由该session给出
	c := session.NewManager(m.service, id, username, string(sender), authFlags, int(appType), limitType, m)

	if c == nil {
		return "", dbusutil.ToError(fmt.Errorf("create session error"))
	}

	path := c.GetDBusPath()

	err := m.service.Export(dbus.ObjectPath(path), c)
	if err != nil {
		logger.Warning(err)
	}

	return path, dbusutil.ToError(err)
}

func (m *Manager) UpdateLimit(updateType session.UpdateType, limitType LimitType, username string, type0 string) {
	if updateType == session.Success {
		m.success(limitType, username, type0)
	} else if updateType == session.Fail {
		m.fail(limitType, username, type0)
	} else if updateType == session.ResetAll {
		m.resetLimits(limitType, username)
	}
}

func (m *Manager) IsLimitAllowed(limitType LimitType, username string, type0 string) bool {
	return m.allowTx(limitType, username, type0)
}

func (m *Manager) GetLimitType(sender dbus.Sender) LimitType {
	execPath, err := GetExecPath(m.service, string(sender))
	if err != nil {
		return Local
	}

	if execPath == "/usr/sbin/sshd" {
		return Remote
	}
	return Local
}

func (m *Manager) RegisterExitCb(id string, fn func()) {
	m.exitCbMu.Lock()
	m.exitCbMap[id] = fn
	m.exitCbMu.Unlock()
}

func (m *Manager) UnRegisterExitCb(id string) {
	m.exitCbMu.Lock()
	delete(m.exitCbMap, id)
	m.exitCbMu.Unlock()
}

func (m *Manager) QueryEncryptKey(t int, rf []int) (resType int, flags []int, pubkey string) {
	var ac encrypt.AsymCrypt
	if len(m.crypts) > t {
		ac = m.crypts[t]
	} else if len(m.crypts) > 0 {
		ac = m.crypts[0]
	} else {
		return -1, nil, ""
	}
	resType, pubkey = ac.PubkeyInfo()
	flags, _ = ac.SupportFlags(rf)
	return
}

func (m *Manager) IsPrivilegesConfigured(masterPath string) bool {
	return m.privileges.isMasterRegistered(masterPath)
}

func (m *Manager) RegisterPrivileges(masterPath string, agentPath string) (int, error) {
	id := m.privileges.register(masterPath, agentPath)
	return id, nil
}

func (m *Manager) UnRegisterPrivileges(id int) {
	m.privileges.unregister(id)
}

func (m *Manager) QueryPrivileges(master string, agent string) bool {
	return m.privileges.allow(master, agent)
}

func (m *Manager) PreOneKeyLogin(sender dbus.Sender, flag int32) (username string, busErr *dbus.Error) {
	//TODO: 需要在这里调用一次指纹认证，并获取是那个用户的指纹通过了认证，返回对应指纹的用户名

	return m.oneKeyLoginRes.username, nil
}

func (m *Manager) GetLimits(sender dbus.Sender, username string) (limitsInfo string, busErr *dbus.Error) {
	limitType := m.GetLimitType(sender)

	limits, err := m.getLimits(limitType, username)
	if err != nil {
		return "", dbusutil.ToError(err)
	}
	// 当没有这个用户的限制信息时，为该用户创建默认的限制信息
	if len(limits) == 0 {
		logger.Debugf("try init limits information for user '%s'", username)
		m.initLimitsByUsername(limitType, username)
		limits, err = m.getLimits(limitType, username)
		if err != nil {
			return "", dbusutil.ToError(err)
		}
	}
	result, err := common.ToJSON(limits)
	logger.Debugf("GetLimits seder %s and result: %s", sender, result)
	return result, dbusutil.ToError(err)
}

func (m *Manager) ResetLimits(sender dbus.Sender, username string) (busErr *dbus.Error) {

	logger.Debugf("user %s reset limits", username)
	pid, err := m.service.GetConnPID(string(sender))
	if err != nil {
		err = fmt.Errorf("fail to get sender PID: %v", err)
		logger.Warning(err)
		return dbusutil.ToError(err)
	}

	procs := procfs.Process(pid)

	status, err := procs.Status()
	if err != nil {
		err = fmt.Errorf("failed to get sender status: %v", err)
		logger.Warning(err)
		return dbusutil.ToError(err)
	}

	uids, err := status.Uids()
	if err != nil {
		err = fmt.Errorf("failed to get sender euid: %v", err)
		logger.Warning(err)
		return dbusutil.ToError(err)
	}

	if len(uids) < 2 {
		err = fmt.Errorf("uid len is %d less than 2", len(uids))
		logger.Warning(err)
		return dbusutil.ToError(err)
	}

	uid := uids[1] // EUID

	if uid != 0 {
		err = fmt.Errorf("not root call ResetLimits")
		logger.Warning(err)
		return dbusutil.ToError(err)
	}
	limitType := m.GetLimitType(sender)
	m.resetLimits(limitType, username)

	return nil
}

func (m *Manager) initLimits() {
	m.limitsMu.Lock()
	m.limits = make(map[LimitType]map[string]map[string]*limit)
	m.limitsMu.Unlock()
	m.loadLimitStates()
	m.initLimitsUserListWatcher()
}

func (m *Manager) initLimitsUserListWatcher() {
	newAccounts := accounts.NewAccounts(m.service.Conn())
	newAccounts.InitSignalExt(m.sysSigLoop, true)
	err := newAccounts.UserList().ConnectChanged(func(hasValue bool, userList []string) {
		if !hasValue {
			return
		}
		existUserList := []string{}
		for _, user := range userList {
			userObj, err := accounts.NewUser(m.service.Conn(), dbus.ObjectPath(user))
			if err != nil {
				continue
			}
			userName, err := userObj.UserName().Get(0)
			if err != nil {
				continue
			}
			existUserList = append(existUserList, userName)
			logger.Debugf("UserList ConnectChanged - accUserlist: %s, %s", user, userName)
		}
		m.limitsMu.Lock()
		for limitType, userLimitInfo := range m.limits {
			for userName, _ := range userLimitInfo {
				isFind := false
				for _, existUser := range existUserList {
					if userName == existUser {
						isFind = true
						break
					}
				}
				logger.Debugf("UserList ConnectChanged - limitUserList: %s, isFind:%t", userName, isFind)
				if !isFind {
					delete(m.limits[limitType], userName)
				}
			}

		}
		m.limitsMu.Unlock()

		m.resetLimits(Local, "")
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) initLimitsByUsername(limitType LimitType, username string) {
	m.limitsMu.Lock()
	defer m.limitsMu.Unlock()

	_, ok := m.limits[limitType]
	if !ok {
		m.limits[limitType] = make(map[string]map[string]*limit)
	}

	_, ok = m.limits[limitType][username]

	if ok {
		return
	}

	m.limits[limitType][username] = make(map[string]*limit)
	for _, authType := range AllAuthTypes {
		m.limits[limitType][username][authType] = nil
	}

	for _, limitConfig := range m.config.Limits {
		type0 := limitConfig.Type
		flag := AuthTypeToFlag(type0)
		if flag == 0 {
			logger.Warningf("invalid auth type %q in limit config", type0)
			continue
		}

		m.limits[limitType][username][type0] = &limit{
			type0:                  type0,
			flag:                   flag,
			unlockSecs:             limitConfig.UnlockSecs,
			maxTries:               limitConfig.MaxTries,
			dynamicLimit:           limitConfig.DynamicLimit,
			dynamicLimitUnlockSecs: limitConfig.DynamicLimitUnlockSecs,
		}
	}

	for _, authType := range AllAuthTypes {
		if m.limits[limitType][username][authType] == nil {
			logger.Debugf("auth type %q use default config", authType)
			m.limits[limitType][username][authType] = &limit{
				type0:      authType,
				flag:       AuthTypeToFlag(authType),
				unlockSecs: 0,
				maxTries:   0,
			}
		}
	}
}

func (m *Manager) allowTx(limitType LimitType, username, type0 string) bool {
	m.limitsMu.Lock()
	defer m.limitsMu.Unlock()

	l := m.limits[limitType][username][type0]
	if l == nil {
		logger.Warningf("not found limit by limit type %s,user %s and type %s", limitType, username, type0)
		return false
	}

	now := time.Now()
	allow, _ := l.allow(now)
	return allow
}

func (m *Manager) fail(limitType LimitType, username, type0 string) {
	m.limitsMu.Lock()

	l := m.limits[limitType][username][type0]
	if l == nil {
		logger.Warningf("not found limit by limit type %s,user %s and type %s", limitType, username, type0)
		m.limitsMu.Unlock()
		return
	}

	now := time.Now()
	l.fail(now)
	m.limitsMu.Unlock()
	states := m.getLimitStates()

	m.saveLimitStates(states)
	m.emitSignalLimitUpdated(username)
}

func (m *Manager) success(limitType LimitType, username string, type0 string) {
	m.limitsMu.Lock()

	l := m.limits[limitType][username][type0]
	if l == nil {
		logger.Warningf("not found limit by limit type %s,user %s and type %s", limitType, username, type0)
		m.limitsMu.Unlock()
		return
	}
	l.reset()
	m.limitsMu.Unlock()
	states := m.getLimitStates()

	m.saveLimitStates(states)
	m.emitSignalLimitUpdated(username)
}

func (m *Manager) resetLimits(limitType LimitType, username string) {
	m.limitsMu.Lock()

	for _, ll := range m.limits[limitType][username] {
		ll.numFailures = 0
		ll.reset()
	}
	m.limitsMu.Unlock()
	states := m.getLimitStates()

	m.saveLimitStates(states)
	m.emitSignalLimitUpdated(username)
}

func (m *Manager) loadLimitStates() {
	var statesV1 map[LimitType]map[string][]LimitState
	var states map[string][]LimitState

	err := loadV1LimitStates(limitStatesV1File, &statesV1)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warning(err)
		} else {
			// 新版limitstate不存在时，取得老版本的limitstate信息
			err = loadLimitStates(limitStatesFile, &states)
			if err != nil {
				if !os.IsNotExist(err) {
					logger.Warning(err)
				}
			} else {
				statesV1 = make(map[LimitType]map[string][]LimitState)
				statesV1[Local] = states
				statesV1[Remote] = states
			}
		}
	}

	for limitType, userLimitInfos := range statesV1 {
		for userName, limit := range userLimitInfos {
			m.initLimitsByUsername(limitType, userName)
			m.limitsMu.Lock()
			for _, state := range limit {
				ll := m.limits[limitType][userName][state.Type]
				if ll == nil {
					continue
				}
				ll.lockAt = state.LockAt
				ll.numFailures = state.NumFailures
			}
			m.limitsMu.Unlock()
		}

	}
}

func (m *Manager) getLimitStates() map[LimitType]map[string][]LimitState {
	m.limitsMu.Lock()
	defer m.limitsMu.Unlock()

	states := make(map[LimitType]map[string][]LimitState)
	for limitType, userLimitInfo := range m.limits {
		states[limitType] = make(map[string][]LimitState)
		for userName, limitInfo := range userLimitInfo {
			for _, ll := range limitInfo {
				states[limitType][userName] = append(states[limitType][userName], LimitState{
					Type:        ll.type0,
					NumFailures: ll.numFailures,
					LockAt:      ll.lockAt,
				})
			}

		}
	}
	return states
}

func (m *Manager) saveLimitStates(states map[LimitType]map[string][]LimitState) {
	logger.Debugf("saveLimitStates")
	m.saveLimitsMu.Lock()
	defer m.saveLimitsMu.Unlock()

	dir := filepath.Dir(limitStatesFile)
	err := os.MkdirAll(dir, 0755) // #nosec G301
	if err != nil {
		logger.Warning(err)
		return
	}

	err = saveLimitStates(states)
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) getLimits(limitType LimitType, username string) ([]LimitForExport, error) {
	m.limitsMu.Lock()
	defer m.limitsMu.Unlock()

	result := make([]LimitForExport, 0)
	_, ok := m.limits[limitType]
	if !ok {
		return result, nil
	}

	limits, ok := m.limits[limitType][username]
	if !ok {
		return result, nil
	}
	now := time.Now()
	for _, l := range limits {
		allow, unlockTime := l.allow(now)
		le := LimitForExport{
			Type:        l.type0,
			UnlockSecs:  l.unlockSecs,
			MaxTries:    l.maxTries,
			Flag:        l.flag,
			NumFailures: l.numFailures,
			Locked:      !allow,
			UnlockTime:  unlockTime,
		}

		result = append(result, le)
	}
	return result, nil
}

func (m *Manager) listenLoginSignalSessionNew() {
	loginManager := login1.NewManager(m.service.Conn())
	loginManager.InitSignalExt(m.sysSigLoop, true)

	_, err := loginManager.ConnectSessionNew(func(sessionId string, sessionPath dbus.ObjectPath) {
		task.GetTaskManager().DoSignalTask("SessionNew", sessionId, sessionPath)
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) listenTTYChanged() {
	for {
		select {
		case ev := <-m.fsWatcher.Events:
			logger.Debugf("file %s changed %d", ev.Name, ev.Op)

			if ev.Op&fsnotify.Write != 0 {
				task.GetTaskManager().DoSignalTask("TTYChanged")
			}

		case err := <-m.fsWatcher.Errors:
			logger.Warning("receive file watcher error:", err)
		}
	}
}

func (m *Manager) DecryptAsymmetric(t int, flags []int, data []byte) (token string, err error) {
	ac := m.crypts[t]
	if ac == nil {
		return "", errors.New("cant get crypts of idx")
	}
	result, err := ac.Decrypt(flags, data)
	if err != nil {
		logger.Errorf("decrypt error: %v", err)
	}
	token = string(result[:])

	return
}

func (m *Manager) DecryptSymmetric(cipherText, key []byte) (token string, err error) {
	token, err = encrypt.Decrypt(cipherText, key)
	if err != nil {
		logger.Errorf("decrypt error: %v", err)
	}
	return
}

func createCrypt(t encrypt.AlgType) (ac encrypt.AsymCrypt, err error) {
	switch t {
	case encrypt.AT_RSA:
		ac, err = encrypt.NewRsa(1024)
	default:
		break
	}
	return
}
