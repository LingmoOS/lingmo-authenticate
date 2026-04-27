package session

import (
	"errors"
	"sync"

	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

type CustomTx struct {
	baseTx

	chanPasswd chan string

	isEnded bool
	endedMu sync.Mutex
}

func newCustomTx() *CustomTx {
	tx := &CustomTx{}
	tx.type0 = AuthTypeCustom
	return tx
}

func (tx *CustomTx) setPassword(password string) {
	go func() {
		tx.endedMu.Lock()
		isEnded := tx.isEnded
		tx.endedMu.Unlock()
		if isEnded {
			return
		}
		tx.chanPasswd <- password
	}()
}

func (tx *CustomTx) end(ct closeType) {
	tx.endedMu.Lock()
	defer tx.endedMu.Unlock()

	logger.Debugf("%v end, close type: %s", tx, ct)
	if tx.isEnded {
		return
	}

	if tx.getDevState() == devStateVerifying {
		logger.Debugf("%v devState is %v", tx, tx.getDevState())
	}

	tx.giveStatus(tx, defaultVerifyStatusEnd)

	logger.Debug(tx, "end return")
	tx.isEnded = true
	close(tx.chanPasswd)
}

func (tx *CustomTx) initTx(prgPath string) error {
	if prgPath != "/usr/bin/dde-lock" && prgPath != "/usr/bin/lightdm-deepin-greeter" {
		return errors.New("Custom authentication is not supported.")
	}
	return nil
}

func (tx *CustomTx) authenticate() error {

	tx.chanPasswd = make(chan string)
	tx.isEnded = false

	tx.giveStatus(tx, defaultVerifyStatusStarted)

	go func() {
		authResult := tx.verify()
		if authResult != nil {
			tx.giveStatus(tx, authResult)
		}
	}()
	return nil
}

func (tx *CustomTx) verify() (result *verifyStatus) {
	select {
	case _, ok := <-tx.chanPasswd:
		// Custom authentication requires no password now
		logger.Debug("verify finish by chan passwd, chan is closed:", ok)
		if ok {
			result = newVerifyStatus(StatusCodeSuccess, true, "")
		}
	}

	logger.Debugf("%v doVerify result: %v", tx, result)

	return result
}

func (tx *CustomTx) getVerifyTip() string {
	return Tr("custom")
}

func (tx *CustomTx) shouldIgnore(status statusCode) bool {
	if status == StatusCodeVerify || status == StatusCodePrompt || status == StatusCodeLocked || status == StatusCodeEnded || status == StatusCodeStarted {
		return true
	}
	return false
}

func (tx *CustomTx) setLockState(s lockState) {
	if tx.getLockState() != s {
		tx.giveStatus(tx, newVerifyStatus(s.toStatusCode(), true, ""))
		if s == lockStateLocked {
			if tx.devState == devStateVerifying {
				tx.end(closeVerify)
			}
		}
	}
	tx.lockState = s
}
