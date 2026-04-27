package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	"pkg.deepin.io/dde/authentication/service/charaDataManger"
)

var (
	irisClaimed   *IrisTx
	irisClaimedMu sync.Mutex
)

type IrisTx struct {
	baseTx
	quit    chan struct{}
	release chan struct{}
	driver  *charaDataManger.CommonDriver
	// 用于charaDataManger与tx传递验证信息
	codeStatusInfo  chan CodeStatusInfo
	uuid            UUID
	serverName      string
	verifySender    string
	isEnded         bool
	endedMu         sync.Mutex
	charaCommonData *charaDataManger.CharaDataManager
	actionId        ActionId
}

func newIrisTx() *IrisTx {
	tx := &IrisTx{}
	tx.type0 = AuthTypeIris
	return tx
}

func (ft *IrisTx) setPassword(password string) {
}

func (ft *IrisTx) end(ct closeType) {
	ft.endedMu.Lock()
	defer ft.endedMu.Unlock()

	logger.Debugf("%v end, close type: %s", ft, ct)
	if ft.isEnded {
		return
	}

	if ft.getDevState() == devStateVerifying {

		logger.Debugf("%v devState is %v", ft, ft.getDevState())
		close(ft.quit)

	}
	<-ft.release
	ft.giveStatus(ft, defaultVerifyStatusEnd)

	logger.Debug(ft, "end return")
	ft.isEnded = true

	ft.charaCommonData.ReleasseActionId(ft.actionId)
	faceClaimed = nil
}

// 判断人脸是否可以用来验证，server有可能为空，则取默认值
func isIrisStatusOk(service string, userName string) bool {
	logger.Debug("isIrisStatusOk")
	charComodata := charaDataManger.GetCharaCommonDataManger()
	if charComodata == nil {
		return false
	}
	driver, claim := charComodata.GetDefaultDriver(service, AuthenticationFlagIris)

	if driver == nil || claim {
		logger.Warningf("not found driver by %s and chara Type %d or driver claim %t", service, AuthenticationFlagFace, claim)
		return false
	}
	uuid, err := charComodata.GetUserUuidByUserName(userName)
	if err != nil {
		return false
	}

	charaInfo := charComodata.GetAvailableCharaInfoByDriverNameAndType(uuid, AuthenticationFlagIris, driver.Configer.Service)

	return len(charaInfo) > 0

}

func cancelLastIrisTx() {
	irisClaimedMu.Lock()
	defer irisClaimedMu.Unlock()

	logger.Debugf("cancelLastIrisTx: %v", irisClaimed)
	if irisClaimed != nil {
		irisClaimed.end(closeAllResource)
		irisClaimed = nil
	}
}

func (ft *IrisTx) initTx(verifySender string, username string, serverName string) error {

	ft.charaCommonData = charaDataManger.GetCharaCommonDataManger()

	if ft.charaCommonData == nil {
		err := fmt.Errorf("not found chara common data manger")
		return err
	}
	ft.serverName = serverName
	uuid, err := ft.charaCommonData.GetUserUuidByUserName(username)
	if err != nil {
		return err
	}
	ft.uuid = uuid
	ft.verifySender = verifySender

	return nil
}

func verifyYourIris() string {
	return Tr("Verify your iris")
}

func (ft *IrisTx) authenticate() error {
	irisClaimedMu.Lock()

	if irisClaimed != nil && irisClaimed != ft {
		irisClaimed.end(closeAllResource)
	}
	ft.release = make(chan struct{})
	ft.quit = make(chan struct{})
	ft.isEnded = false
	irisClaimed = ft

	ft.giveStatus(ft, defaultVerifyStatusStarted)
	ft.giveStatus(ft, newVerifyStatus(StatusCodePrompt, false, verifyYourIris()))

	go func() {

		authResult := ft.verify()

		close(ft.release)

		if authResult != nil {
			ft.giveStatus(ft, authResult)
		}
		irisClaimedMu.Unlock()

	}()

	return nil
}

func (ft *IrisTx) verify() (result *verifyStatus) {
	logger.Debug(ft, "Verify start")

	driver, claim := ft.charaCommonData.GetDefaultDriver(ft.serverName, AuthenticationFlagIris)
	if driver == nil || claim {
		logger.Warning(ft, "get driver error claim %t", claim)
		result = newVerifyStatus(StatusCodeError, false, "get driver error")
		return
	}
	ft.serverName = driver.Configer.Service
	ft.codeStatusInfo = make(chan CodeStatusInfo, 5)
	var err error
	ft.actionId, err = ft.charaCommonData.GenActionId(dbus.Sender(ft.verifySender), ft.serverName, Verify, AuthenticationFlagIris, ft.codeStatusInfo)
	if err != nil {
		logger.Warning(ft, err)
		result = newVerifyStatus(StatusCodeError, false, err.Error())
		return
	}

	charaInfo := ft.charaCommonData.GetAvailableCharaInfoByDriverNameAndType(ft.uuid, AuthenticationFlagIris, ft.serverName)

	var chara []string
	for _, val := range charaInfo {

		chara = append(chara, string(val.Chara))
	}
	logger.Warning(chara)

	_, err = driver.Core.VerifyStart(0, chara, string(ft.actionId))
	if err != nil {
		logger.Warning(err)
		return
	}

	timer := time.NewTicker(time.Second * 15)
	defer func() {
		logger.Debug(ft, "stop verify")
		timer.Stop()
		err = driver.Core.VerifyStop(0, string(ft.actionId))
		if err != nil {
			logger.Warning(err)
		}
		logger.Debug("stop verify OVER")
	}()

loop:
	for {
		select {
		case <-ft.quit:
			logger.Debug("<-ft.quit")
			break loop
		case result := <-ft.codeStatusInfo:
			code := IrisVerifyStatus(result.Code)

			if code.IsEndedStatus() {
				logger.Warningf("iris end code %d", code)
				ft.sendDoneResult(code)
				break loop
			} else if code.IsContinue() {

				logger.Warningf("iris continue code %d", code)
				err = driver.Core.VerifyStop(0, string(ft.actionId))
				if err != nil {
					logger.Warning(err)
					ft.giveStatus(ft, newVerifyStatus(StatusCodeFailure, false, "fail"))
					break loop
				}

				_, err = driver.Core.VerifyStart(0, chara, string(ft.actionId))
				if err != nil {
					logger.Warning(err)
					ft.giveStatus(ft, newVerifyStatus(StatusCodeFailure, false, "faile"))
					break loop
				}

			} else {
				logger.Warningf("face verify code %d", code)
				ft.giveStatus(ft, newVerifyStatus(StatusCodeVerify, false, code.String()))
			}

		case <-timer.C:
			ft.giveStatus(ft, newVerifyStatus(StatusCodeFailure, false, "time out"))
			return
		}
	}
	return
}

func (ft *IrisTx) getVerifyTip() string {
	return Tr("iris")
}

func (ft *IrisTx) sendDoneResult(verifyStatus IrisVerifyStatus) {
	var stdStatus statusCode
	switch verifyStatus {
	case IrisVerifySuccess:
		stdStatus = StatusCodeSuccess
	case IrisVerifyDisconnected:
		stdStatus = StatusCodeFailure
	default:
		stdStatus = StatusCodeUnknown
	}
	ft.giveStatus(ft, newVerifyStatus(stdStatus, true, ""))
}
func (ft *IrisTx) shouldIgnore(status statusCode) bool {
	if status == StatusCodeVerify || status == StatusCodePrompt || status == StatusCodeLocked || status == StatusCodeEnded || status == StatusCodeStarted {
		return true
	}
	return false
}

func (ft *IrisTx) setLockState(s lockState) {
	if ft.getLockState() != s {
		ft.giveStatus(ft, newVerifyStatus(s.toStatusCode(), true, ""))
		if s == lockStateLocked {
			if ft.devState == devStateVerifying {
				ft.end(closeVerify)
			}
		}
	}
	ft.lockState = s
}
