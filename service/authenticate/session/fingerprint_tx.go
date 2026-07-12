package session

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil"

	"github.com/godbus/dbus"
	authenticate "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.authenticate"
	"pkg.deepin.io/dde/authentication/pkg/fingerprint"
	pkgfp "pkg.deepin.io/dde/authentication/pkg/fingerprint"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

var (
	claimed   *FingerprintTx
	claimedMu sync.Mutex
)

type FingerprintTx struct {
	baseTx
	quit    chan struct{}
	release chan struct{}

	fpObj      authenticate.Fingerprint
	signalLoop *dbusutil.SignalLoop

	isEnded bool
	endedMu sync.Mutex
}

func newFingerprintTx() *FingerprintTx {
	tx := &FingerprintTx{}
	tx.type0 = AuthTypeFingerprint
	return tx
}

func (ft *FingerprintTx) setPassword(password string) {
}

func (ft *FingerprintTx) end(ct closeType) {
	ft.endedMu.Lock()
	defer ft.endedMu.Unlock()

	logger.Debugf("%v end, close type: %s", ft, ct)
	if ft.isEnded {
		return
	}

	if ft.getDevState() == devStateVerifying {
		logger.Debugf("%v devState is %v", ft, ft.getDevState())
		close(ft.quit)
		<-ft.release
	}

	ft.giveStatus(ft, defaultVerifyStatusEnd)

	logger.Debug(ft, "end return")
	ft.isEnded = true

	if ct == closeAllResource {
		ft.fpObj.RemoveAllHandlers()
		claimed = nil
	}
}

func hasFingerprintDevice() (bool, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return false, err
	}

	fpObj := authenticate.NewFingerprint(sysBus)
	defaultDevice, err := fpObj.DefaultDevice().Get(0)
	if err != nil {
		return false, err
	}
	if defaultDevice == "" {
		return false, nil
	}

	return true, nil
}

func cancelLastFingerprintTx() {
	claimedMu.Lock()
	defer claimedMu.Unlock()

	logger.Debugf("cancelLastFingerprintTx: %v", claimed)
	if claimed != nil {
		claimed.end(closeAllResource)
	}
	claimed = nil
}

func (ft *FingerprintTx) checkCapability(cap int32) (bool, error) {
	defaultDevice, err := ft.fpObj.DefaultDevice().Get(0)
	if err != nil {
		return false, err
	}

	devicesStr, err := ft.fpObj.Devices().Get(0)
	if err != nil {
		return false, err
	}

	var devices []fingerprint.DeviceInfo
	err = json.Unmarshal([]byte(devicesStr), &devices)
	if err != nil {
		return false, err
	}

	for _, v := range devices {
		if v.Name == defaultDevice {
			if (v.Capability & cap) != 0 {
				return true, nil
			}
			break
		}
	}

	return false, nil
}

func listFingers(username string) []string {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		logger.Debug("connect to system bus failed", err)
		return nil
	}

	newFingerprint := authenticate.NewFingerprint(sysBus)

	fingers, err := newFingerprint.ListFingers(0, username)
	if err != nil {
		return nil
	}
	return fingers
}

func (ft *FingerprintTx) initTx(username string) error {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		logger.Debug("connect to system bus failed", err)
		return err
	}

	ft.fpObj = authenticate.NewFingerprint(sysBus)

	if username == pkgfp.EmptyUsername {
		canOneKeyLogin, err := ft.checkCapability(fingerprint.CapabilityOneKeyLogin)
		if err != nil {
			return err
		}
		if !canOneKeyLogin {
			return errors.New("the device does not support one-key login")
		}
	} else {
		fingers, err := ft.fpObj.ListFingers(0, username)
		if err != nil {
			return err
		}
		if len(fingers) == 0 {
			return errors.New("no fingers")
		}
	}
	ft.signalLoop = dbusutil.NewSignalLoop(sysBus, 10)
	ft.fpObj.InitSignalExt(ft.signalLoop, true)
	ft.signalLoop.Start()

	return nil
}

func verifyYourFingerprint() string {
	return Tr("Verify your fingerprint")
}

func (ft *FingerprintTx) authenticate() error {
	claimedMu.Lock()
	defer claimedMu.Unlock()

	if claimed != nil && claimed != ft {
		claimed.end(closeAllResource)
	}
	claimed = ft

	err := ft.fpObj.Claim(0, ft.username(), true)
	if err != nil {
		logger.Debug("claim fingerprint device failed", err)
		return err
	}

	ft.release = make(chan struct{})
	ft.quit = make(chan struct{})
	ft.isEnded = false

	ft.giveStatus(ft, defaultVerifyStatusStarted)
	ft.giveStatus(ft, newVerifyStatus(StatusCodePrompt, false, verifyYourFingerprint()))

	go func() {
		authResult := ft.verify()

		logger.Debugf("%v type: fingerprint, do claim < false >", ft)
		err := ft.fpObj.Claim(0, ft.username(), false)
		if err != nil {
			logger.Warning(ft, err)
		}

		close(ft.release)

		if authResult != nil {
			ft.giveStatus(ft, authResult)
		}

	}()
	return nil
}

type verifyResult struct {
	code int32
	msg  string
}

func (ft *FingerprintTx) verify() (result *verifyStatus) {
	//ft.fpObj.InitSignalExt(ft.parent.m.sysSigLoop, true)

	verifyResultCh := make(chan verifyResult)

	_, err := ft.fpObj.ConnectVerifyStatus(func(username string, code int32, msg string) {
		if ft.username() == pkgfp.EmptyUsername {
			//ft.parent.m.setOneKeyLoginResult(ft.parent.id, ft.type0, username, code == pkgfp.VerifyStatusMatch)
			return
		}

		if username != ft.username() {
			logger.Warningf("username %s != %s", username, ft.username())
			return
		}
		result := verifyResult{
			code: code,
			msg:  msg,
		}
		logger.Debug(ft, "signal VerifyStatus", result)
		//ft.parent.m.emitSignalStatusVerify(ft.parent.id, AuthenticationFlagFingerprint, int(code), msg)
		select {
		case verifyResultCh <- result:
		case <-time.After(100 * time.Millisecond):
		}
	})
	if err != nil {
		logger.Warning(err)
	}

	result = ft.doVerify(verifyResultCh)
	logger.Debugf("%v doVerify result: %v", ft, result)

	return result
}

func (ft *FingerprintTx) doVerify(verifyResultCh chan verifyResult) (result *verifyStatus) {
	logger.Debug(ft, "Verify start")
	err := ft.fpObj.Verify(0, "any")
	if err != nil {
		logger.Warning(err)
		result = newVerifyStatus(StatusCodeError, false, err.Error())
		return
	}

	var code int32 = -1
loop:
	for {
		select {
		//case <-time.After(10 * time.Second):
		//	logger.Warning("timed out")
		//	result = AuthResultTimeout{}
		//	break loop
		case <-ft.quit:
			break loop
		case result := <-verifyResultCh:
			done, err := pkgfp.IsVerifyStatusDone(int(result.code))
			if err != nil {
				logger.Warning(err)
			}
			logger.Debug(ft, "is verifyStatus done:", pkgfp.VerifyStatusToString(int(result.code)), done)
			if done {
				code = result.code
				break loop
			}
		}
	}

	logger.Debug(ft, "stop verify")
	err = ft.fpObj.StopVerify(0)
	if err != nil {
		logger.Warning(ft, "call StopVerify err:", err)
		result = newVerifyStatus(StatusCodeError, false, err.Error())
		return
	}

	switch code {
	case -1:
		//if !ft.parent.isEnded() {
		//	ft.parent.m.emitSignalStatusVerify(ft.parent.id, AuthenticationFlagFingerprint, pkgfp.VerifyStatusTakenByOthers, "")
		//}
	case pkgfp.VerifyStatusMatch:
		result = newVerifyStatus(StatusCodeSuccess, true, "")
	case pkgfp.VerifyStatusNoMatch:
		result = newVerifyStatus(StatusCodeFailure, true, "")
	case pkgfp.VerifyStatusError:
		logger.Warning(ft, "verify error")
		result = newVerifyStatus(StatusCodeError, false, "Verify error")
	}
	return
}

func (ft *FingerprintTx) getVerifyTip() string {
	return Tr("fingerprint")
}

func (ft *FingerprintTx) shouldIgnore(status statusCode) bool {
	if status == StatusCodeVerify || status == StatusCodePrompt || status == StatusCodeLocked || status == StatusCodeEnded || status == StatusCodeStarted {
		return true
	}
	return false
}

func (ft *FingerprintTx) setLockState(s lockState) {
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
