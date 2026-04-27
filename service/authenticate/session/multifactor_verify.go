package session

import (
	"strings"
	"sync"
	"time"

	. "pkg.deepin.io/dde/authentication/service/authcommon"
	mf "pkg.deepin.io/dde/authentication/service/multifactor"
)

type MFAResInfo struct {
	res ResType
	msg string
}

type multiFactorVerify struct {
	baseController
	conf             *mf.Config
	passNumber       int
	expectPassNumber int
	resultMap        map[int]*MFAResInfo
	resultMapMux     sync.Mutex
	authMsg          []string
	resultCh         chan Tx
	once             sync.Once
	mfaAuthFlags     int32 // 保存此次认证开启的认证因子
	endMu            sync.Mutex
	isTTYPrg         bool
}

func (m *multiFactorVerify) sendStatus(tx Tx) {
	if !m.isEnded() {
		m.resultCh <- tx
	} else {
		status := tx.getVerifyStatus()
		logger.Debugf("%v: ended, shouldIgnore status: %s, msg: %s", m, status.getStatusCode(), status.String())
	}
}

func newMultiFactorVerify(appType int, isTTYPrg bool) *multiFactorVerify {
	conf := mf.MfConfig.GetConfig(appType)
	if conf == nil {
		return nil
	}

	m := multiFactorVerify{resultMap: make(map[int]*MFAResInfo), resultCh: make(chan Tx, 10), isTTYPrg: isTTYPrg}
	m.conf = conf
	return &m
}

func mfaVerifyPrompt() string {
	return Tr("Multiple verification methods are required")
}

func (m *multiFactorVerify) authenticate(flag int, timeout int) int {
	m.once.Do(func() {
		// 需要先发
		m.proxy.emitStatus(AllAuthenticationFlag, StatusCodePrompt, TranslateWrapper(m.username, m.isTTYPrg, mfaVerifyPrompt()))
		go m.listenResultCh()
	})

	var hasFailed int
	for _, tx := range m.txs {
		if flag&AuthTypeToFlag(tx.getType()) != 0 {
			hasFailed++
			if tx.getDevState() == devStateIdle && tx.getLockState() == lockStateUnlock {
				logger.Debugf("%v: authenticate for %s, timeout is: %d", m, tx.getType(), timeout)
				err := tx.authenticate()
				if err != nil {
					logger.Warning(err)
					continue
				}

				hasFailed--
				if timeout != -1 && timeout > 0 {
					txTmp := tx
					time.AfterFunc(time.Second*time.Duration(timeout), func() {
						logger.Debugf("%v: type %s timeout, end it", m, txTmp.getType())
						txTmp.end(closeVerify)
					})
				}
			} else {
				logger.Debugf("%v: %s is %s, lockState is %s, can not start", m, tx.getType(), tx.getDevState(), tx.getLockState())
			}
		}
	}

	return hasFailed
}

func (m *multiFactorVerify) end(s statusCode, flag int) {
	ct := closeVerify
	if flag == AllAuthenticationFlag {
		if m.isEnded() {
			return
		}

		m.markEnded()
		if s == StatusCodeSuccess {
			m.proxy.updateLimits(s, AllAuthenticationFlag)
		}
		close(m.resultCh)
		ct = closeAllResource
	}
	for _, tx := range m.txs {
		if AuthTypeToFlag(tx.getType())&flag != 0 {
			if tx.getDevState() != devStateIdle {
				tx.end(ct)
			} else {
				logger.Debugf("%v: %s state is %s, ignore it", m, tx.getType(), tx.getDevState())
			}
		}
	}
}

func (m *multiFactorVerify) listenResultCh() {
	if err := m.setExpectResult(); err != nil {
		m.emitFailResult(err.Error())
		return
	}

	for {
		tx, ok := <-m.resultCh
		if !ok {
			logger.Debugf("%v: result ch closed", m)
			return
		}
		if tx == nil {
			logger.Debugf("%v: receive invalid tx", m)
			continue
		}

		status := tx.getVerifyStatus()
		if status == nil {
			logger.Debugf("%v: receive invalid tx", m)
			continue
		}
		logger.Debugf("%v: receive result, type: %s", m, tx.getType())

		m.proxy.emitStatus(AuthTypeToFlag(tx.getType()), status.getStatusCode(), TranslateWrapper(m.username, m.isTTYPrg, status.String()))

		if !tx.shouldIgnore(status.getStatusCode()) {
			m.proxy.updateLimits(status.getStatusCode(), AuthTypeToFlag(tx.getType()))
			m.setResult(tx.getType(), status.getStatusCode() == StatusCodeSuccess, status.String())

			res := m.getVerifyResult()
			if res == StatusCodeFailure || res == StatusCodeSuccess {
				m.proxy.emitStatus(AllAuthenticationFlag, res, m.getAuthMsg())
				m.proxy.updateLimits(res, AllAuthenticationFlag)
			}
		} else {
			logger.Debugf("%v: type %s, shouldIgnore for status %s", m, tx.getType(), status.getStatusCode())
		}

	}
}

func (m *multiFactorVerify) checkTx(username string, appType int, refFlag int32) int32 {

	var flag int32
	authList := mf.GetAuthTypeList(m.conf)
	for _, at := range authList {
		flag |= int32(at)
	}

	m.mfaAuthFlags = flag
	return flag
}

func (m *multiFactorVerify) getVerifyResult() statusCode {
	if m.passNumber < m.expectPassNumber {
		return StatusCodeVerify
	}

	for _, resInfo := range m.resultMap {
		if resInfo.res == ResFailed {
			return StatusCodeFailure
		} else if resInfo.res == ResDefault {
			return StatusCodeVerify
		}
	}

	return StatusCodeSuccess
}

func (m *multiFactorVerify) setResult(type0 string, result bool, msg string) {
	m.resultMapMux.Lock()
	defer m.resultMapMux.Unlock()

	t := AuthTypeToFlag(type0)
	// 只可对本次开启的认证设置结果
	if int32(t)&m.mfaAuthFlags != 0 {
		// 对于每种认证方式,可以设置多次结果
		if m.resultMap[t].res == ResDefault {
			m.passNumber++
		}
		if result {
			m.resultMap[t].res = ResSuccess
		} else {
			m.resultMap[t].res = ResFailed
		}
		m.resultMap[t].msg = msg
	}
}

func (m *multiFactorVerify) clearResult(type0 string) {
	m.resultMapMux.Lock()
	defer m.resultMapMux.Unlock()

	t := AuthTypeToFlag(type0)
	if int32(t)&m.mfaAuthFlags != 0 {
		if m.resultMap[t].res != ResDefault {
			m.passNumber--
		}
		m.resultMap[t].res = ResDefault
		m.resultMap[t].msg = ""
	}
}

func (m *multiFactorVerify) getAuthMsg() string {
	var authMsgSlice []string
	for type0, resInfo := range m.resultMap {
		if resInfo.res != ResDefault {
			authMsgSlice = append(authMsgSlice, AuthFlagToType(type0)+": "+resInfo.msg)
		}
	}
	return strings.Join(authMsgSlice, ", ")
}

func (m *multiFactorVerify) setExpectResult() error {
	authList := mf.GetAuthTypeList(m.conf)
	for _, c := range authList {
		m.resultMap[c] = &MFAResInfo{res: ResDefault}
	}
	m.expectPassNumber = len(authList)
	return nil
}

func (m *multiFactorVerify) emitFailResult(msg string) {
	m.proxy.emitStatus(AllAuthenticationFlag, StatusCodeFailure, msg)
}

func (m *multiFactorVerify) emitSuccessResult(msg string) {
	m.proxy.emitStatus(AllAuthenticationFlag, StatusCodeSuccess, msg)
}

func (m *multiFactorVerify) genPrompt(txs []Tx) string {
	numOfTx := len(txs)
	pinIndex := -1
	if numOfTx == 0 {
		return ""
	}

	var prompt string
	var typeList []string
	for id, tx := range txs {
		typeList = append(typeList, tx.getVerifyTip())
		if tx.getType() == AuthTypeUKey {
			pinIndex = id
		}
	}

	if numOfTx == 1 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Verify your %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Enter your %s"), typeList...)
			} else {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, "%s", SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 2 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Verify your %s and %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Enter your %s and %s"), typeList...)
			} else {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("%s and %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 3 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Verify your %s, %s and %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Enter your %s, %s and %s"), typeList...)
			} else {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("%s, %s and %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 4 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Verify your %s, %s, %s and %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Enter your %s, %s, %s and %s"), typeList...)
			} else {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("%s, %s, %s and %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 5 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Verify your %s, %s, %s, %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Enter your %s, %s, %s, %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("%s, %s, %s, %s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 6 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Verify your %s, %s, %s, %s, %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("Enter your %s, %s, %s, %s, %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(m.username, m.isTTYPrg, Tr("%s, %s, %s, %s, %s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	}
	// todo: 有更多时需要添加判断

	return prompt
}

// 获取认证因子的信息,包括认证的优先级,输入方式,可以用于指示前端做认证先后排序,根据不同的输入类型做显示不同的认证框
func (m *multiFactorVerify) genAuthFactors() []authFactor {
	// todo
	var authFactors []authFactor
	var offset int
	existType := make(map[string]bool)

	for _, tx := range m.txs {
		if existType[tx.getType()] {
			continue
		}
		af := authFactor{
			AuthType:  AuthTypeToFlag(tx.getType()),
			Priority:  offset + AuthTypeToPriority(tx.getType()),
			InputType: AuthTypeToInputType(tx.getType()),
			Required:  false,
		}
		authFactors = append(authFactors, af)
	}
	return authFactors
}
