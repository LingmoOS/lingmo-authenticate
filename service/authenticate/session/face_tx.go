package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/godbus/dbus"
	"pkg.deepin.io/dde/authentication/service/authcommon"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
	"pkg.deepin.io/dde/authentication/service/charaDataManger"
)

var (
	faceClaimed   *FaceTx
	faceClaimedMu sync.Mutex
)

type faceVerifyResult struct {
	statusCode authcommon.FaceVerifyStatus
	msg        string
}

type FaceTx struct {
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

func newFaceTx() *FaceTx {
	tx := &FaceTx{}
	tx.type0 = AuthTypeFace
	return tx
}

func (ft *FaceTx) setPassword(password string) {
}

func (ft *FaceTx) end(ct closeType) {
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
func isFaceStatusOk(service string, userName string) bool {
	logger.Debug("isFaceStatusOk")
	charComodata := charaDataManger.GetCharaCommonDataManger()
	if charComodata == nil {
		return false
	}
	driver, claim := charComodata.GetDefaultDriver(service, AuthenticationFlagFace)

	if driver == nil || claim {
		logger.Warningf("not found driver by %s and chara Type %d or driver claim %t", service, AuthenticationFlagFace, claim)
		return false
	}
	uuid, err := charComodata.GetUserUuidByUserName(userName)
	if err != nil {
		return false
	}

	charaInfo := charComodata.GetAvailableCharaInfoByDriverNameAndType(uuid, AuthenticationFlagFace, driver.Configer.Service)

	return len(charaInfo) > 0

}

func cancelLastFaceTx() {
	faceClaimedMu.Lock()
	defer faceClaimedMu.Unlock()

	logger.Debugf("cancelLastFaceTx: %v", faceClaimed)
	if faceClaimed != nil {
		faceClaimed.end(closeAllResource)
		faceClaimed = nil
	}
}

func (ft *FaceTx) initTx(verifySender string, username string, serverName string) error {

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

func verifyYourFace() string {
	return Tr("Verify your face")
}

func (ft *FaceTx) authenticate() error {
	faceClaimedMu.Lock()

	if faceClaimed != nil && faceClaimed != ft {
		faceClaimed.end(closeAllResource)
	}
	ft.release = make(chan struct{})
	ft.quit = make(chan struct{})
	ft.isEnded = false
	faceClaimed = ft

	ft.giveStatus(ft, defaultVerifyStatusStarted)
	ft.giveStatus(ft, newVerifyStatus(StatusCodePrompt, false, verifyYourFace()))

	go func() {

		authResult := ft.verify()
		close(ft.release)

		if authResult != nil {
			ft.giveStatus(ft, authResult)
		}
		faceClaimedMu.Unlock()

	}()

	return nil
}

func (ft *FaceTx) verify() (result *verifyStatus) {
	logger.Debug(ft, "Verify start")

	driver, claim := ft.charaCommonData.GetDefaultDriver(ft.serverName, AuthenticationFlagFace)
	if driver == nil || claim {
		logger.Warning(ft, "get driver error claim %t", claim)
		result = newVerifyStatus(StatusCodeError, false, "get driver error")
		return
	}
	ft.serverName = driver.Configer.Service
	ft.codeStatusInfo = make(chan CodeStatusInfo, 5)
	var err error
	ft.actionId, err = ft.charaCommonData.GenActionId(dbus.Sender(ft.verifySender), ft.serverName, Verify, AuthenticationFlagFace, ft.codeStatusInfo)
	if err != nil {
		logger.Warning(ft, err)
		result = newVerifyStatus(StatusCodeError, false, err.Error())
		return
	}

	charaInfo := ft.charaCommonData.GetAvailableCharaInfoByDriverNameAndType(ft.uuid, AuthenticationFlagFace, ft.serverName)

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
			code := FaceVerifyStatus(result.Code)

			if code.IsEndedStatus() {
				logger.Warningf("face end code %d", code)
				ft.sendDoneResult(code)
				break loop
			} else if code.IsContinue() {

				logger.Warningf("face continue code %d", code)
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

func (ft *FaceTx) getVerifyTip() string {
	return Tr("face")
}

func (ft *FaceTx) sendDoneResult(verifyStatus FaceVerifyStatus) {
	var stdStatus statusCode
	switch verifyStatus {
	case FaceVerifySuccess:
		stdStatus = StatusCodeSuccess
	case FaceVerifyDisconnected:
		stdStatus = StatusCodeFailure
	case FaceVerifyException:
		stdStatus = StatusCodeException
	default:
		stdStatus = StatusCodeUnknown
	}
	ft.giveStatus(ft, newVerifyStatus(stdStatus, true, ""))
}
func (ft *FaceTx) shouldIgnore(status statusCode) bool {
	if status == StatusCodeVerify || status == StatusCodePrompt || status == StatusCodeLocked || status == StatusCodeEnded || status == StatusCodeStarted {
		return true
	}
	return false
}

func (ft *FaceTx) setLockState(s lockState) {
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
