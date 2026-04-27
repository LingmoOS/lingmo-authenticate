package session

type statusCode int

const (
	StatusCodeSuccess   statusCode = iota // 成功
	StatusCodeFailure                     // 失败
	StatusCodeCancel                      // 取消
	StatusCodeTimeout                     // 超时
	StatusCodeError                       // 错误
	StatusCodeVerify                      // 验证中
	StatusCodeException                   // 设备异常
	StatusCodePrompt                      // 设备提示
	StatusCodeStarted                     // 认证已启动
	StatusCodeEnded                       // 认证已结束
	StatusCodeLocked                      // 认证已锁定
	StatusCodeRecover                     // 设备恢复,对应 StatusCodeException
	StatusCodeUnlocked                    // 设备解锁,对应 StatusCodeLocked
	StatusCodeUnknown                     // 未知设备状态
)

var (
	defaultVerifyStatusEnd     = newVerifyStatus(StatusCodeEnded, true, "")
	defaultVerifyStatusCancel  = newVerifyStatus(StatusCodeCancel, true, "")
	defaultVerifyStatusStarted = newVerifyStatus(StatusCodeStarted, true, "")
)

type verifyStatus struct {
	s   statusCode
	msg string
}

func newVerifyStatus(s statusCode, defaultTr bool, trMsg string) *verifyStatus {
	status := &verifyStatus{s: s}
	if defaultTr {
		status.msg = status.s.String()
	} else {
		status.msg = trMsg
	}
	return status
}

func (dc *verifyStatus) getStatusCode() statusCode {
	return dc.s
}

func (dc *verifyStatus) String() string {
	return dc.msg
}

func (s statusCode) toInt() int {
	return int(s)
}

func (s statusCode) String() string {
	switch s {
	case StatusCodeSuccess:
		return "Success"
	case StatusCodeFailure:
		return "Failed"
	case StatusCodeCancel:
		return "Cancel"
	case StatusCodeTimeout:
		return "Timeout"
	case StatusCodeError:
		return "Error"
	case StatusCodeVerify:
		return "Verifying"
	case StatusCodeException:
		return "Device except"
	case StatusCodeStarted:
		return "Started"
	case StatusCodeEnded:
		return "Ended"
	case StatusCodeLocked:
		return "Locked"
	case StatusCodePrompt:
		return "Prompt"
	case StatusCodeRecover:
		return "Recovered"
	case StatusCodeUnlocked:
		return "Unlocked"
	}
	return "Unknown status"
}
