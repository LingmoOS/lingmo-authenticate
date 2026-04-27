package authcommon

type IrisVerifyStatus int

const (
	IrisVerifySuccess IrisVerifyStatus = iota // 成功
	IrisVerifyTooBig                          // 太大
	IrisVerifyTooSmall
	IrisVerifyNoFace
	IrisVerifyNotClear           // 不清晰
	IrisVerifyBrightness         // 亮度
	IrisVerifyEyesClose          // 闭目
	IrisVerifyCancel             // 取消
	IrisVerifyError              // 崩溃
	IrisVerifyDisconnected       // 厂商断开连接
	IrisVerifySenderDisconnected // 发起方断开连接
)

func (fvs IrisVerifyStatus) IsEndedStatus() bool {
	switch fvs {
	case IrisVerifySuccess, IrisVerifyDisconnected, IrisVerifySenderDisconnected:
		return true
	}
	return false
}
func (fvs IrisVerifyStatus) IsContinue() bool {
	switch fvs {
	case IrisVerifyError:
		return true
	}
	return false
}

func (fvs IrisVerifyStatus) String() string {
	switch fvs {
	case IrisVerifySuccess:
		return Tr("Verification successful")
	case IrisVerifyTooBig:
		return Tr("Keep away from the camera")
	case IrisVerifyTooSmall:
		return Tr("Get closer to the camera")
	case IrisVerifyNoFace:
		return Tr("Iris not found")
	case IrisVerifyNotClear:
		return Tr("Make sure the camera lens is clean")
	case IrisVerifyBrightness:
		return Tr("Do not enroll in dark, bright or backlit environments")
	case IrisVerifyEyesClose:
		return Tr("Keep your eyes wide open")
	}
	return Tr("Unknown error")
}

type IrisEnrollStatus int

const (
	IrisEnrollSuccess IrisEnrollStatus = iota // 成功
	IrisEnrollTooBig                          // 太大
	IrisEnrollTooSmall
	IrisEnrollNoFace
	IrisEnrollNotClear           // 不清晰
	IrisEnrollBrightness         // 亮度
	IrisEnrollEyesClose          // 闭目
	IrisEnrollCancel             // 取消
	IrisEnrollError              // 崩溃
	IrisEnrollDisconnected       // 厂商断开连接
	IrisEnrollSenderDisconnected // 发起方断开连接
)
