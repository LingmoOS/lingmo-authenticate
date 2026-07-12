package session

import (
	"errors"
	"fmt"
	"sync"

	. "pkg.deepin.io/dde/authentication/service/authcommon"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/pam"
)

type PasswordTx struct {
	baseTx
	session          passwordSession
	sessionId        int // 用于判断当前 sessionId 与 session 中传递过来的 id 是否一致,不一致则说明此 id 已过时,忽略此消息
	nextSessionId    int
	nextSessionIdMux sync.Mutex
}

func newPasswordTx(type0 string) *PasswordTx {
	tx := &PasswordTx{}
	tx.type0 = type0
	return tx
}

func (pt *PasswordTx) setPassword(password string) {
	pt.session.setToken(password)
}

func (pt *PasswordTx) authenticate() error {
	pt.nextSessionIdMux.Lock()
	pt.nextSessionId++
	pt.sessionId = pt.nextSessionId
	pt.nextSessionIdMux.Unlock()

	pt.session = newPamSession()
	err := pt.session.start(pt.nextSessionId, pt.type0, pt.userName, "", pt)
	if err != nil {
		return nil
	}

	return pt.session.authenticate()
}

func password() string {
	return Tr("Password: ")
}

func (pt *PasswordTx) end(ct closeType) {
	logger.Debugf("%v end, close type: %s", pt, ct)
	if pt.session != nil {
		pt.session.end()
	}
	pt.giveStatus(pt, defaultVerifyStatusEnd)
	pt.sessionId = -1
}

func (pt *PasswordTx) getVerifyTip() string {
	return Tr("password")
}

// 需要忽略不计入认证结果的状态
func (pt *PasswordTx) shouldIgnore(status statusCode) bool {
	if status == StatusCodeVerify || status == StatusCodePrompt || status == StatusCodeLocked || status == StatusCodeEnded || status == StatusCodeStarted {
		return true
	}
	return false
}

func (pt *PasswordTx) setLockState(s lockState) {

	if pt.getLockState() != s {
		pt.giveStatus(pt, newVerifyStatus(s.toStatusCode(), true, ""))
		if s == lockStateLocked {
			if pt.devState == devStateVerifying {
				pt.end(closeVerify)
			}
		}
	}
	pt.lockState = s
}

func (pt *PasswordTx) sendStatus(id int, s *verifyStatus) {
	if id == pt.sessionId {
		pt.giveStatus(pt, s)
	} else {
		logger.Warningf("%v ignore status %v", pt, s)
	}
}

type passwordResultI interface {
	sendStatus(int, *verifyStatus)
}

type passwordSession interface {
	start(sessionId int, type0 string, username string, service string, sessionResult passwordResultI) error
	authenticate() error
	setToken(string)
	end()
}

type pamSession struct {
	id       int
	core     *pam.Transaction
	username string
	result   passwordResultI
	type0    string
	ch       chan string
	ended    bool
	endedMux sync.Mutex
	tokenMux sync.Mutex
}

func newPamSession() *pamSession {
	return &pamSession{}
}

var FakePasswordTxEnabled = ""

func (ps *pamSession) doAuth() {
	var err error
	if FakePasswordTxEnabled == "1" {
		err = ps.doAuthFake()
	} else {
		err = ps.doAuthAux()
	}

	status := newVerifyStatus(StatusCodeSuccess, true, "")
	if err != nil {
		status = newVerifyStatus(StatusCodeFailure, true, "")
	}

	err = ps.core.End(ps.core.LastStatus())
	if err != nil {
		logger.Warning(err)
	}

	ps.result.sendStatus(ps.id, status)
}

func (ps *pamSession) doAuthAux() error {
	// meet the requirement of pam_unix.so nullok_secure option,
	// allows any user with a blank password to unlock.
	err := ps.core.SetItemStr(pam.Tty, "tty1")
	if err != nil {
		logger.Warning("failed to set item tty:", err)
	}

	err = ps.core.Authenticate(0)
	return err
}

func (ps *pamSession) doAuthFake() error {
	password := <-ps.ch
	switch ps.type0 {
	case AuthTypePassword:
		if password == "pa" {
			return nil
		}
	case AuthTypeActiveDirectory:
		if password == "ad" {
			return nil
		}
	}
	return errors.New("password wrong")
}

func (ps *pamSession) RespondPAM(style pam.Style, msg string) (string, error) {
	switch style {
	case pam.PromptEchoOn:
		return ps.username, nil
	case pam.PromptEchoOff:
		//todo: 需要用一个二进制去调pam模块,以获取翻译
		ps.result.sendStatus(ps.id, newVerifyStatus(StatusCodePrompt, false, password()))
		password := <-ps.ch
		return password, nil
	case pam.ErrorMsg:
		logger.Warning("errorMsg:", msg)
		return "", nil
	case pam.TextInfo:
		ps.result.sendStatus(ps.id, newVerifyStatus(StatusCodePrompt, false, msg))
		logger.Warning("textInfo:", msg)
		return "", nil

	default:
		return "", fmt.Errorf("invalid pam style %v", style)
	}
}

func (ps *pamSession) start(id int, type0 string, username string, service string, sessionResult passwordResultI) error {
	ps.id = id
	ps.username = username
	ps.result = sessionResult
	ps.type0 = type0
	ps.ch = make(chan string)

	pamService := ""
	switch ps.type0 {
	case AuthTypePassword:
		pamService = "deepin_pam_unix"
	case AuthTypeActiveDirectory:
		pamService = "deepin_pam_ad"
	default:
		panic(fmt.Errorf("invalid passwordTx type %q", ps.type0))
	}

	var err error
	ps.core, err = pam.Start(pamService, username, ps)
	if err != nil {
		return err
	}
	return nil
}

func (ps *pamSession) authenticate() error {
	ps.result.sendStatus(ps.id, newVerifyStatus(StatusCodeStarted, true, ""))
	go ps.doAuth()
	return nil
}

func (ps *pamSession) setToken(token string) {
	ps.tokenMux.Lock()
	defer ps.tokenMux.Unlock()

	ps.ch <- token
}

func (ps *pamSession) end() {
	ps.endedMux.Lock()
	defer ps.endedMux.Unlock()

	if ps.ended {
		return
	}

	ps.ended = true
	close(ps.ch)
}
