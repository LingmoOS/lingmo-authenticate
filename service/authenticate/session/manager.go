package session

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/LingmoOS/golang-github-lingmo-go-lib/strv"

	authenticate "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.authenticate"

	"github.com/godbus/dbus"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/log"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	mf "pkg.deepin.io/dde/authentication/service/multifactor"
	"pkg.deepin.io/dde/authentication/service/task"
)

//go:generate dbusutil-gen em -type Manager

const (
	dBusAuthenticateSessionPath = "/com/lingmo/daemon/Authenticate/Session/_"
)

type authFactor struct {
	AuthType  int
	Priority  int
	InputType int
	Required  bool
}

type Manager struct {
	proxy Proxy

	service    *dbusutil.Service
	signalLoop *dbusutil.SignalLoop

	id                 string
	appType            int
	dbusPath           string
	verifySender       string
	refFlag            int32
	quitMethod         quitMethod
	quited             bool
	canceled           bool
	txs                []Tx
	controller         Controller
	publicKey          string
	algType            int
	cryptFlags         []int
	statusResult       statusCode
	finalResultGiven   bool
	signalMu           sync.Mutex
	isStarted          bool
	isTTYPrg           bool
	limitType          LimitType
	pId                int
	symmetricKey       string
	ttyChangedFuncList []func()

	// prop
	IsMFA  bool
	Prompt string
	// dbusutil-gen: equal=nil
	FactorsInfo []authFactor
	Username    string
	PINLen      int
	PrgPath     string
	quitMu      sync.Mutex

	//no lint
	signals *struct {
		Status struct {
			flag   int
			status int
			msg    string
		}
	}
}

var logger = log.NewLogger("deepin-authenticate/session")

type UpdateType int

const (
	Fail UpdateType = iota
	Success
	ResetAll
)

type Proxy interface {
	IsLimitAllowed(LimitType, string, string) bool
	UpdateLimit(UpdateType, LimitType, string, string)
	RegisterPrivileges(string, string) (int, error)
	UnRegisterPrivileges(int)
	QueryPrivileges(string, string) bool
	IsPrivilegesConfigured(string) bool
	RegisterExitCb(string, func())
	UnRegisterExitCb(string)
	QueryEncryptKey(int, []int) (int, []int, string)
	DecryptAsymmetric(int, []int, []byte) (string, error)
	DecryptSymmetric([]byte, []byte) (string, error)
}

func isTTYPrg(s *dbusutil.Service, sender string) (bool, error) {
	pid, err := s.GetConnPID(sender)
	if err != nil {
		return false, err
	}

	link, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/0", pid))
	if err != nil {
		return false, err
	}

	if strings.Contains(link, "tty") {
		return true, nil
	}

	return false, nil
}

func (m *Manager) GetInterfaceName() string {
	return "com.lingmo.daemon.Authenticate.Session"
}

func NewManager(service *dbusutil.Service, id string, username string,
	sender string, refFlag int32, appType int, limitType LimitType, proxy Proxy) *Manager {

	m := Manager{service: service, quitMethod: autoQuit, id: id,
		verifySender: sender, refFlag: refFlag, appType: appType, proxy: proxy,
		statusResult: StatusCodeFailure, limitType: limitType}

	if username != "" {
		m.Username = username
	}
	m.dbusPath = dBusAuthenticateSessionPath + m.id

	err := m.initData()
	if err != nil {
		return nil
	}
	return &m
}

// 监听 UpdateLimited 信号, 当该用户的限制信息变更时, 需要查询该次认证是否有认证因子被锁定,如果有,则设置为锁定状态
func (m *Manager) listenSignalUpdateLimited() {
	m.signalLoop = dbusutil.NewSignalLoop(m.service.Conn(), 10)
	m.signalLoop.Start()

	newAuthenticate := authenticate.NewAuthenticate(m.service.Conn())
	newAuthenticate.InitSignalExt(m.signalLoop, true)

	_, err := newAuthenticate.ConnectLimitUpdated(func(username string) {
		if username == m.Username {
			logger.Debugf("%v: received signal UpdateLimited", m.controller)
			for _, tx := range m.txs {
				if !m.proxy.IsLimitAllowed(m.limitType, username, tx.getType()) {
					logger.Debugf("%v: type %s limit state is not allowed", m.controller, tx.getType())
					tx.setLockState(lockStateLocked)
				} else {
					tx.setLockState(lockStateUnlock)
				}
			}
		}
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (m *Manager) checkAvailableTx(flag int32) int32 {
	var retFlag int32
	if flag&AuthenticationFlagPassword != 0 {
		retFlag |= AuthenticationFlagPassword
	}
	if flag&AuthenticationFlagFingerprint != 0 {
		can, _ := hasFingerprintDevice()
		if can {
			fingers := listFingers(m.Username)
			if fingers != nil && len(fingers) != 0 {
				retFlag |= AuthenticationFlagFingerprint
			}
		}
	}
	if flag&AuthenticationFlagActiveDirectory != 0 {
		retFlag |= AuthenticationFlagActiveDirectory
	}
	if flag&AuthenticationFlagUKey != 0 {
		if m.hasValidUKeyDevice() && m.isUKeySupportedUser() {
			retFlag |= AuthenticationFlagUKey
		}
	}
	if flag&AuthenticationFlagFace != 0 {
		if m.isFaceStatusOk() {
			retFlag |= AuthenticationFlagFace
		}
	}
	if flag&AuthenticationFlagIris != 0 {
		if m.isIrisStatusOk() {
			retFlag |= AuthenticationFlagIris
		}
	}
	if flag&AuthenticationFlagCustom != 0 {
		retFlag |= AuthenticationFlagCustom
	}
	return retFlag
}

func (m *Manager) isFaceStatusOk() bool {
	var service string
	if m.IsMFA {
		config := mf.GetMFAObj().GetConfig(m.appType)
		if config == nil {
			return false
		}
		c := config.GetAuthTypeConfig(AuthTypeFace)
		if c == nil {
			return false
		}

		service = c.Service
	}

	return isFaceStatusOk(service, m.Username)
}

func (m *Manager) isIrisStatusOk() bool {
	var service string
	if m.IsMFA {
		config := mf.GetMFAObj().GetConfig(m.appType)
		if config == nil {
			return false
		}
		c := config.GetAuthTypeConfig(AuthTypeIris)
		if c == nil {
			return false
		}

		service = c.Service
	}

	return isIrisStatusOk(service, m.Username)
}
func (m *Manager) GetConfigServerName(authType string) string {
	var service string
	if m.IsMFA {
		config := mf.GetMFAObj().GetConfig(m.appType)
		if config == nil {
			return service
		}
		c := config.GetAuthTypeConfig(authType)
		if c == nil {
			return service
		}

		service = c.Service
	}

	return service
}

func (m *Manager) checkUnLockedTx(flag int32) int32 {
	var retFlag int32
	if flag&AuthenticationFlagPassword != 0 {
		if m.proxy.IsLimitAllowed(m.limitType, m.Username, AuthTypePassword) {
			retFlag |= AuthenticationFlagPassword
		}
	}
	if flag&AuthenticationFlagFingerprint != 0 {
		if m.proxy.IsLimitAllowed(m.limitType, m.Username, AuthTypeFingerprint) {
			retFlag |= AuthenticationFlagFingerprint
		}
	}
	if flag&AuthenticationFlagActiveDirectory != 0 {
		if m.proxy.IsLimitAllowed(m.limitType, m.Username, AuthTypeActiveDirectory) {
			retFlag |= AuthenticationFlagActiveDirectory
		}
	}
	if flag&AuthenticationFlagUKey != 0 {
		if m.proxy.IsLimitAllowed(m.limitType, m.Username, AuthTypeUKey) {
			retFlag |= AuthenticationFlagUKey
		}
	}
	if flag&AuthenticationFlagFace != 0 {
		if m.proxy.IsLimitAllowed(m.limitType, m.Username, AuthTypeFace) {
			retFlag |= AuthenticationFlagFace
		}
	}
	if flag&AuthenticationFlagIris != 0 {
		if m.proxy.IsLimitAllowed(m.limitType, m.Username, AuthTypeIris) {
			retFlag |= AuthenticationFlagIris
		}
	}
	return retFlag
}

func (m *Manager) genTTYChangedCb(flag int32) task.Func {
	if flag&AuthenticationFlagFingerprint != 0 {
		m.ttyChangedFuncList = append(m.ttyChangedFuncList, cancelLastFingerprintTx)
	}
	if flag&AuthenticationFlagFace != 0 {
		m.ttyChangedFuncList = append(m.ttyChangedFuncList, cancelLastFaceTx)
	}

	return func(id string, paras ...interface{}) bool {
		for _, fn := range m.ttyChangedFuncList {
			go fn()
		}
		return true
	}
}

func (m *Manager) initData() error {
	isTTYPrg, err := isTTYPrg(m.service, m.verifySender)
	if err != nil {
		return nil
	}

	m.isTTYPrg = isTTYPrg

	execPath, err := GetExecPath(m.service, m.verifySender)
	if err != nil {
		return err
	}
	m.PrgPath = execPath

	if mf.MfConfig.IsProgramConfigured(m.appType) && mf.MfConfig.IsProgramEnabled(m.PrgPath) {
		m.IsMFA = true
		logger.Debugf("program %s is support multiFactor", execPath)
	} else {
		logger.Debugf("program %s is not support multiFactor", execPath)
	}

	if m.proxy.IsPrivilegesConfigured(m.PrgPath) {
		m.IsMFA = false
		m.refFlag = AuthenticationFlagPassword
		logger.Debugf("program %s has configuration of privileges, change to SFA", execPath)
	} else if m.IsMFA {
		// GetExecPath 判断过, 此处不可能为 nil
		m.controller = newMultiFactorVerify(m.appType, m.isTTYPrg)

		refFlags := m.controller.checkTx(m.Username, m.appType, m.refFlag)
		availableFlags := m.checkAvailableTx(refFlags)

		if availableFlags != refFlags {
			// 无法满足多因条件,走单因认证
			logger.Debugf("can not open MFA, use SFA")
			m.IsMFA = false
		} else {
			// 走多因认证,不用考虑是否锁定
			m.addTxs(refFlags)
		}
	}

	if !m.IsMFA {
		m.controller = newNormalVerify(m.isTTYPrg)
		availableFlags := m.checkAvailableTx(m.controller.checkTx(m.Username, m.appType, m.refFlag))
		m.addTxs(availableFlags)
	}

	m.controller.init(m.id, m.Username, m.txs, m)
	m.Prompt = m.controller.genPrompt(m.txs)
	m.FactorsInfo = m.controller.genAuthFactors()
	m.PINLen = m.getPINLength()

	m.listenSignalUpdateLimited()
	m.proxy.RegisterExitCb(m.id, func() {
		m.endAll()
	})

	task.GetTaskManager().AddSignalTask("TTYChanged", "TTYChanged", m.genTTYChangedCb(m.refFlag), false)
	return nil
}

func (m *Manager) getUKeyConfig() *mf.AuthTypeConfig {
	var config *mf.Config
	if m.IsMFA {
		config = mf.MfConfig.GetConfig(m.appType)
		if config == nil {
			return nil
		}
	} else {
		config = &mf.Config{
			RequestVerificationType: []*mf.AuthTypeConfig{
				{Service: "*", Type: mf.AuthTypeToMfaType(AuthTypeUKey)}}}
	}

	uKeyConfig := config.GetAuthTypeConfig(AuthTypeUKey)
	if uKeyConfig == nil {
		return nil
	}
	return uKeyConfig
}

func (m *Manager) hasValidUKeyDevice() bool {
	uKeyConfig := m.getUKeyConfig()
	if uKeyConfig == nil {
		return false
	}

	devices := hasValidUKeyDevices()

	if len(devices) == 0 {
		return false
	}

	if uKeyConfig.IsUseDefaultService() {
		return true
	}

	if strv.Strv(devices).Contains(uKeyConfig.Service) {
		return true
	}

	return false
}

func (m *Manager) isUKeySupportedUser() bool {
	uKeyConfig := m.getUKeyConfig()
	if uKeyConfig == nil {
		return false
	}
	return isUKeySupportedUser(m.Username, uKeyConfig.Service, uKeyConfig.IsUseDefaultService())
}

func (m *Manager) getPINLength() int {
	uKeyConfig := m.getUKeyConfig()
	if uKeyConfig == nil {
		return 0
	}
	return getPINLength(uKeyConfig.Service, m.Username, uKeyConfig.IsUseDefaultService())
}

func (m *Manager) GetDBusPath() string {
	return m.dbusPath
}

func (m *Manager) addTx(tx Tx) {
	allowed := m.proxy.IsLimitAllowed(m.limitType, m.Username, tx.getType())
	lockState := lockStateUnlock
	if !allowed {
		lockState = lockStateLocked
	}
	tx.init(m.Username, m.id, m.appType, lockState, m.controller)
	m.txs = append(m.txs, tx)
	logger.Debugf("<session id = %s > add < %s >", m.id, tx.getType())
}

func (m *Manager) addTxs(flag int32) {
	if flag&AuthenticationFlagPassword != 0 {
		tx := newPasswordTx(AuthTypePassword)
		if tx != nil {
			m.addTx(tx)
		}
	}
	if flag&AuthenticationFlagFingerprint != 0 {
		tx := newFingerprintTx()
		if tx != nil {
			err := tx.initTx(m.Username)
			if err != nil {
				logger.Warning(err)
			} else {
				m.addTx(tx)
			}
		}
	}
	if flag&AuthenticationFlagActiveDirectory != 0 {
		tx := newPasswordTx(AuthTypeActiveDirectory)
		if tx != nil {
			m.addTx(tx)
		}
	}
	if flag&AuthenticationFlagUKey != 0 {
		tx := newUKeyTx(m.IsMFA)
		if tx != nil {
			m.addTx(tx)
		}
	}
	if flag&AuthenticationFlagFace != 0 {
		tx := newFaceTx()
		if tx != nil {
			servername := m.GetConfigServerName(AuthTypeFace)
			err := tx.initTx(m.verifySender, m.Username, servername)
			if err != nil {
				logger.Warning(err)
			} else {
				m.addTx(tx)
			}
		}
	}

	if flag&AuthenticationFlagIris != 0 {
		tx := newIrisTx()
		if tx != nil {
			servername := m.GetConfigServerName(AuthTypeIris)
			err := tx.initTx(m.verifySender, m.Username, servername)
			if err != nil {
				logger.Warning(err)
			} else {
				m.addTx(tx)
			}
		}
	}

	if flag&AuthenticationFlagCustom != 0 {
		tx := newCustomTx()
		if tx != nil {
			err := tx.initTx(m.PrgPath)
			if err != nil {
				logger.Warning(err)
			} else {
				m.addTx(tx)
			}
		}
	}
}

func (m *Manager) quit() {
	m.quitMu.Lock()
	if !m.quited {
		logger.Debugf("session %s quited", m.dbusPath)
		m.service.StopExportByPath(dbus.ObjectPath(m.dbusPath))
		m.signalLoop.Stop()
		m.quited = true
		m.proxy.UnRegisterExitCb(m.id)
	}
	m.quitMu.Unlock()
}

func (m *Manager) end(flag int, status *verifyStatus) {
	logger.Debugf("%v: end action, flag is %s, status is %s, msg is %s", m.controller, AuthFlagToType(flag), status.getStatusCode(), status.String())
	m.controller.end(status.getStatusCode(), flag)
}

// 如果认证已经给出了结果,调用End则为结束
// 如果认证没有给出结果,调用End则为取消
func (m *Manager) endAll() {
	status := defaultVerifyStatusEnd
	if !m.finalResultGiven {
		status = defaultVerifyStatusCancel
	}

	logger.Debugf("%v: end action, flag is %s, status is %s, msg is %s", m.controller, AuthFlagToType(AllAuthenticationFlag), status.getStatusCode(), status.String())
	m.emitStatus(AllAuthenticationFlag, status.getStatusCode(), TranslateWrapper(m.Username, m.isTTYPrg, status.String()))
	m.controller.end(status.getStatusCode(), AllAuthenticationFlag)

	if !m.canceled {
		if m.quitMethod == autoQuit {
			m.quit()
		} else {
			time.AfterFunc(time.Second*5, m.quit)
		}
		m.canceled = true
	}
}

func (m *Manager) updateLimits(status statusCode, authFlag int) {
	logger.Debugf("%v: update limit for %s's %s", m.controller, m.Username, AuthFlagToType(authFlag))

	if authFlag == AllAuthenticationFlag {
		if status == StatusCodeSuccess {
			m.proxy.UpdateLimit(ResetAll, m.limitType, m.Username, AuthFlagToType(authFlag))
		}
	} else {
		if status == StatusCodeSuccess {
			// 产品需求,密码通过的同时,解锁所有限制
			if authFlag == AuthenticationFlagPassword {
				m.proxy.UpdateLimit(ResetAll, m.limitType, m.Username, AuthFlagToType(authFlag))
			} else {
				m.proxy.UpdateLimit(Success, m.limitType, m.Username, AuthFlagToType(authFlag))
			}
		} else if status == StatusCodeFailure || status == StatusCodeException {
			m.proxy.UpdateLimit(Fail, m.limitType, m.Username, AuthFlagToType(authFlag))
		}
	}
}

func (m *Manager) checkOwner(sender string) (string, error) {
	senderExecPath, err := GetExecPath(m.service, sender)
	if err != nil {
		return "", err
	}
	if senderExecPath != m.PrgPath {
		return "", fmt.Errorf("permission denied")
	}
	return senderExecPath, nil
}
