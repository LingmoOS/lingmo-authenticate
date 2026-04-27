package session

import (
	"fmt"
	"sync"
)

type closeType int

const (
	closeVerify closeType = iota
	closeAllResource
)

func (ct closeType) String() string {
	if ct == closeAllResource {
		return "< close all resource >"
	} else if ct == closeVerify {
		return "< close verify process >"
	}
	return "< unknown close type >"
}

type lockState int

const (
	lockStateUnlock lockState = iota
	lockStateLocked
)

func (s lockState) toStatusCode() statusCode {
	if s == lockStateLocked {
		return StatusCodeLocked
	}
	return StatusCodeUnlocked
}

func (s lockState) String() string {
	if s == lockStateUnlock {
		return "< unlock >"
	}
	return "< locked >"
}

type lockStateI interface {
	setLockState(lockState)
	getLockState() lockState
}

type devStateI interface {
	getDevState() devState
	setDevState(devState)
}

type Tx interface {
	devStateI
	lockStateI

	init(username string, dbusPath string, appType int, lockState lockState, ds deviceStatusProxy)
	authenticate() error
	setPassword(password string)
	end(closeType)
	getVerifyStatus() *verifyStatus
	getType() string
	getVerifyTip() string
	shouldIgnore(flag statusCode) bool
}

type devState int

const (
	devStateIdle devState = iota
	devStateVerifying
	devStateDevException
	devStateEnded
)

func (d devState) String() string {
	if d == devStateIdle {
		return "< device is idle >"
	} else if d == devStateVerifying {
		return "< device is in verifying >"
	} else if d == devStateDevException {
		return "< device is abnormal >"
	} else if d == devStateEnded {
		return "< device verify process is ended >"
	} else {
		return "< unknown device state >"
	}
}

func statusCodeToDevState(status statusCode) devState {
	if status == StatusCodeSuccess || status == StatusCodeError || status == StatusCodeFailure || status == StatusCodeLocked {
		return devStateEnded
	} else if status == StatusCodePrompt || status == StatusCodeVerify || status == StatusCodeStarted {
		return devStateVerifying
	} else if status == StatusCodeRecover || status == StatusCodeUnlocked || status == StatusCodeEnded || status == StatusCodeCancel {
		return devStateIdle
	}
	return devStateDevException
}

type baseTx struct {
	type0     string
	status    *verifyStatus
	statusMux sync.Mutex
	userName  string
	appType   int
	devState  devState
	devStatus deviceStatusProxy
	lockState lockState
	id        string
}

func (bt *baseTx) getLockState() lockState {
	return bt.lockState
}

func (bt *baseTx) init(username string, id string, appType int, lockState lockState, ds deviceStatusProxy) {
	bt.id = id
	bt.userName = username
	bt.appType = appType
	bt.devStatus = ds
	bt.devState = devStateIdle
	bt.lockState = lockState
}

func (bt *baseTx) username() string {
	return bt.userName
}

func (bt *baseTx) getType() string {
	return bt.type0
}

func (bt *baseTx) clone(tx Tx) Tx {
	t := newVirtualTx(bt, tx)
	logger.Debugf("virtualTx status addr is %p, %p", t.status, &t.status)
	return t
}

func (bt *baseTx) giveStatus(tx Tx, s *verifyStatus) {
	if s == nil {
		return
	}
	bt.statusMux.Lock()
	defer bt.statusMux.Unlock()

	bt.status = s
	logger.Debugf("status addr is %p, %p", bt.status, &bt.status)
	logger.Debugf("%v give result: %v", tx, s)
	bt.setDevState(statusCodeToDevState(s.s))
	bt.devStatus.sendStatus(bt.clone(tx))
}

func (bt *baseTx) getVerifyStatus() *verifyStatus {
	return bt.status
}

func (bt *baseTx) getDevState() devState {
	return bt.devState
}

func (bt *baseTx) setDevState(s devState) {
	bt.devState = s
}

type deviceStatusProxy interface {
	sendStatus(Tx)
}

func (bt *baseTx) String() string {
	return fmt.Sprintf("< id = %s, type = %s >", bt.id, bt.type0)
}

type virtualTx struct {
	*baseTx
	tx Tx
}

func newVirtualTx(bt *baseTx, tx Tx) *virtualTx {
	vt := &virtualTx{baseTx: &baseTx{}, tx: tx}
	vt.init(bt.userName, bt.id, bt.appType, bt.lockState, bt.devStatus)
	vt.type0 = bt.type0
	vt.status = bt.status
	return vt
}

func (v *virtualTx) setLockState(s lockState) {
	v.tx.setLockState(s)
}

func (v *virtualTx) authenticate() error {
	return v.tx.authenticate()
}

func (v *virtualTx) setPassword(password string) {
	v.tx.setPassword(password)
}

func (v *virtualTx) end(ct closeType) {
	v.tx.end(ct)
}

func (v *virtualTx) getVerifyTip() string {
	return v.tx.getVerifyTip()
}

func (v *virtualTx) shouldIgnore(flag statusCode) bool {
	return v.tx.shouldIgnore(flag)
}
