package fingerprint

import (
	"fmt"
)

const (
	EmptyUsername = "*"
	EmptyUUID     = "00000000-0000-0000-0000-000000000000"
)

type DeviceInfo struct {
	Name       string `json:"name"`
	Available  bool   `json:"available"`
	Capability int32  `json:"capability"`
}

const (
	CapabilityOneKeyLogin int32 = 1 << iota
)

const (
	VerifyStatusMatch = iota
	VerifyStatusNoMatch
	VerifyStatusError
	VerifyStatusRetry
	VerifyStatusDisconnected
	VerifyStatusTakenByOthers
)

const (
	VerifyStatusRetrySubcodeSwipeTooShort = iota + 1
	VerifyStatusRetrySubcodeFingerNotCentered
	VerifyStatusRetrySubcodeRemoveAndRetry
	VerifyStatusRetrySubcodeTouchTimeShort
	VerifyStatusRetrySubcodeQualityBad // 图像质量太差
)

const (
	VerifyStatusErrorSubcodeUnknown = iota + 1
	VerifyStatusErrorSubcodeUnavailable
)

func IsVerifyStatusDone(statusCode int) (bool, error) {
	switch statusCode {
	case VerifyStatusMatch, VerifyStatusNoMatch, VerifyStatusError, VerifyStatusDisconnected:
		return true, nil
	case VerifyStatusRetry:
		return false, nil
	default:
		return false, fmt.Errorf("invalid verify status code %d", statusCode)
	}
}

func VerifyStatusToString(statusCode int) string {
	switch statusCode {
	case VerifyStatusMatch:
		return "match"
	case VerifyStatusNoMatch:
		return "no-match"
	case VerifyStatusError:
		return "error"
	case VerifyStatusRetry:
		return "retry"
	case VerifyStatusDisconnected:
		return "disconnected"
	default:
		return fmt.Sprintf("invalid-verify-status(%d)", statusCode)
	}
}

const (
	EnrollStatusCompleted = iota
	EnrollStatusFailed
	EnrollStatusStagePassed
	EnrollStatusRetry
	EnrollStatusDisconnected
)

func EnrollStatusToString(statusCode int) string {
	switch statusCode {
	case EnrollStatusCompleted:
		return "completed"
	case EnrollStatusFailed:
		return "failed"
	case EnrollStatusStagePassed:
		return "stage-passed"
	case EnrollStatusRetry:
		return "retry"
	case EnrollStatusDisconnected:
		return "disconnected"
	default:
		return fmt.Sprintf("invalid-enroll-status(%d)", statusCode)
	}
}

// enroll failed sub-codes:
const (
	EnrollStatusFailedSubcodeUnknownError = iota + 1
	EnrollStatusFailedSubcodeTemplateDuplicated
	EnrollStatusFailedSubcodeInterrupt
	EnrollStatusFailedSubcodeDataFull
)

// enroll retry sub-codes:
const (
	EnrollStatusRetrySubcodeTouchTimeShort     = iota + 1 // 触摸时间过短
	EnrollStatusRetrySubcodeQualityBad                    // 图像质量太差
	EnrollStatusRetrySubcodeRepetitionRateHigh            // 重复率太高
	EnrollStatusRetrySubcodeExist                         // 已经存在
	EnrollStatusRetrySubcodeSwipeTooShort
	EnrollStatusRetrySubcodeFingerNotCentered
	EnrollStatusRetrySubcodeRemoveAndRetry
)
