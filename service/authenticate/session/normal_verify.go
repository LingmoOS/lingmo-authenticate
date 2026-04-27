package session

import (
	"fmt"
	"strings"
	"sync"
	"time"

	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

type normalVerify struct {
	baseController
	resultCh    chan Tx
	txResultMap map[string]statusCode
	mapMu       sync.Mutex
	authMsg     []string
	once        sync.Once
	inputMap    map[string]bool
	hasInput    bool
	isTTYPrg    bool
}

func newNormalVerify(isTTYPrg bool) *normalVerify {
	return &normalVerify{isTTYPrg: isTTYPrg, resultCh: make(chan Tx, 10), txResultMap: make(map[string]statusCode), inputMap: make(map[string]bool)}
}

func (g *normalVerify) initInputMap() {
	for _, tx := range g.txs {
		if AuthTypeToInputType(tx.getType()) == InputTypeKeyboard {
			g.inputMap[tx.getType()] = false
		}
	}
}

func (g *normalVerify) authenticate(flag int, timeout int) int {
	g.once.Do(func() {
		logger.Debugf("%v: start listenResultCh", g)
		g.initResultMap()
		g.initInputMap()
		go g.listenResultCh()
	})

	var hasFailed int
	var emitPrompt bool
	var startedTxs []Tx
	if flag == AllAuthenticationFlag {
		flag = AllAuthenticationTypeMask
		emitPrompt = true
	}
	for _, tx := range g.txs {
		if flag&AuthTypeToFlag(tx.getType()) != 0 {
			hasFailed++
			if tx.getDevState() == devStateIdle && tx.getLockState() == lockStateUnlock {
				logger.Debugf("%v: authenticate for %s, timeout is: %d", g, tx.getType(), timeout)
				err := tx.authenticate()
				if err != nil {
					logger.Warning(err)

					continue
				}

				hasFailed--
				if timeout != -1 && timeout > 0 {
					txTmp := tx
					time.AfterFunc(time.Second*time.Duration(timeout), func() {
						logger.Debugf("%v: type %s timeout, end it", g, txTmp.getType())
						txTmp.end(closeVerify)
					})
				}

				startedTxs = append(startedTxs, tx)
			} else {
				logger.Debugf("%v: %s is %s, lockState is %s, can not start", g, tx.getType(), tx.getDevState(), tx.getLockState())
			}
		}
	}
	if emitPrompt {
		g.proxy.emitStatus(AllAuthenticationFlag, StatusCodePrompt, g.genPrompt(startedTxs))
	}
	return hasFailed
}

func (g *normalVerify) end(s statusCode, flag int) {
	ct := closeVerify
	if flag == AllAuthenticationFlag {
		if g.isEnded() {
			return
		}
		g.markEnded()

		close(g.resultCh)

		ct = closeAllResource
	}

	for _, tx := range g.txs {
		if AuthTypeToFlag(tx.getType())&flag != 0 {
			if tx.getDevState() != devStateIdle {
				tx.end(ct)
			} else {
				logger.Debugf("%v: %s state is %s, ignore it", g, tx.getType(), tx.getDevState())
			}
		}
	}
}

func (g *normalVerify) initResultMap() {
	for _, tx := range g.txs {
		g.txResultMap[tx.getType()] = StatusCodeUnknown
	}
}

func (g *normalVerify) addTxStatus(tx Tx, status *verifyStatus) {
	g.mapMu.Lock()
	if _, ok := g.txResultMap[tx.getType()]; ok {
		g.txResultMap[tx.getType()] = status.getStatusCode()
		g.authMsg = append(g.authMsg, fmt.Sprintf("%s: %s", tx.getType(), status.String()))
		g.inputMap[tx.getType()] = true
	} else {
		logger.Debugf("%v, type %s is not authenticate group %s", g, tx.getType(), g.pathId)
	}
	g.mapMu.Unlock()
}

func (g *normalVerify) adjudgeFinalResult() statusCode {
	g.mapMu.Lock()
	defer g.mapMu.Unlock()
	var res statusCode = StatusCodeVerify
	for type0, v := range g.txResultMap {
		if v == StatusCodeSuccess {
			return StatusCodeSuccess
		} else if v == StatusCodeFailure {
			shouldIgnore := false
			if g.hasInput {
				// 如果有输入类型，且包含未完成的，则忽略该次失败结果
				for _, hasInput := range g.inputMap {
					if !hasInput {
						shouldIgnore = true
					}
				}
			}
			if !shouldIgnore {
				res = StatusCodeFailure
				logger.Debugf("ignore input type %s val %s", type0, v)
			}
		}
	}

	return res
}

func (g *normalVerify) getFinalAuthMsg() string {
	return strings.Join(g.authMsg, ", ")
}

func (g *normalVerify) listenResultCh() {
	for {
		tx, ok := <-g.resultCh
		if !ok {
			logger.Debugf("%v: result ch closed", g)
			return
		}

		if tx == nil {
			logger.Debugf("%v: receive invalid tx", g)
			continue
		}

		status := tx.getVerifyStatus()
		if status == nil {
			logger.Debugf("%v: receive invalid tx", g)
			continue
		}

		logger.Debugf("%v: receive result, type: %s", g, tx.getType())

		g.proxy.emitStatus(AuthTypeToFlag(tx.getType()), status.getStatusCode(), TranslateWrapper(g.username, g.isTTYPrg, status.String()))

		if !tx.shouldIgnore(status.getStatusCode()) {
			// 给单独的认证类型更新 limit 信息
			g.proxy.updateLimits(status.getStatusCode(), AuthTypeToFlag(tx.getType()))
			g.addTxStatus(tx, status)
			// 如果有输入类型，则需要做特殊判断
			if AuthTypeToInputType(tx.getType()) == InputTypeKeyboard {
				g.hasInput = true
			}

			res := g.adjudgeFinalResult()
			if res == StatusCodeSuccess || res == StatusCodeFailure {
				g.proxy.emitStatus(AllAuthenticationFlag, res, g.getFinalAuthMsg())
				g.proxy.updateLimits(res, AllAuthenticationFlag)
			}
		} else {
			logger.Debugf("%v: type %s, shouldIgnore for status %s", g, tx.getType(), status.getStatusCode())
		}
	}
}

func (g *normalVerify) checkTx(username string, appType int, refFlag int32) int32 {
	return refFlag
}

func (g *normalVerify) genPrompt(txs []Tx) string {
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
			prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Verify your %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Enter your %s"), typeList...)
			} else {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, "%s", SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 2 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Verify your %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Enter your %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("%s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 3 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Verify your %s, %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Enter your %s, %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("%s, %s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 4 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Verify your %s, %s, %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Enter your %s, %s, %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("%s, %s, %s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 5 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Verify your %s, %s, %s, %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Enter your %s, %s, %s, %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("%s, %s, %s, %s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	} else if numOfTx == 6 {
		if IsBiometricAuth(typeList[0]) {
			prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Verify your %s, %s, %s, %s, %s or %s"), typeList...)
		} else {
			if pinIndex == 0 {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("Enter your %s, %s, %s, %s, %s or %s"), typeList...)
			} else {
				prompt = TranslateWrapper(g.username, g.isTTYPrg, Tr("%s, %s, %s, %s, %s or %s"), SliceFirstDataCharUpper(typeList)...)
			}
		}
	}
	// todo: 有更多时需要添加判断

	return prompt
}

func (g *normalVerify) genAuthFactors() []authFactor {
	var authFactors []authFactor
	for _, tx := range g.txs {
		af := authFactor{
			AuthType:  AuthTypeToFlag(tx.getType()),
			Priority:  AuthTypeToPriority(tx.getType()),
			InputType: AuthTypeToInputType(tx.getType()),
			Required:  false,
		}
		authFactors = append(authFactors, af)
	}
	return authFactors
}

func (g *normalVerify) sendStatus(tx Tx) {
	if !g.isEnded() {
		g.resultCh <- tx
	} else {
		status := tx.getVerifyStatus()
		logger.Debugf("%v: ended, shouldIgnore status: %s, msg: %s", g, status.getStatusCode(), status.String())
	}
}
