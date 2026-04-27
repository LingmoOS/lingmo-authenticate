package authcommon

type FaceVerifyStatus int

const (
	FaceVerifySuccess FaceVerifyStatus = iota
	FaceVerifyNotRealHuman
	FaceVerifyFaceNotCenter
	FaceVerifyFaceTooBig
	FaceVerifyFaceTooSmall
	FaceVerifyNoFace
	FaceVerifyTooManyFace
	FaceVerifyFaceNotClear
	FaceVerifyBrightness
	FaceVerifyFaceCovered
	FaceVerifyCancel
	FaceVerifyError
	FaceVerifyException
	FaceVerifyDisconnected       // 厂商断开连接
	FaceVerifySenderDisconnected // 发起方断开连接
)

func (fvs FaceVerifyStatus) IsEndedStatus() bool {
	switch fvs {
	case FaceVerifySuccess, FaceVerifyDisconnected, FaceVerifySenderDisconnected, FaceVerifyException:
		return true
	}
	return false
}
func (fvs FaceVerifyStatus) IsContinue() bool {
	switch fvs {
	case FaceVerifyError, FaceVerifyNotRealHuman:
		return true
	}
	return false
}

func (fvs FaceVerifyStatus) String() string {
	switch fvs {
	case FaceVerifySuccess:
		return Tr("Verification successful")
	case FaceVerifyNotRealHuman:
		return Tr("Position your face please")
	case FaceVerifyFaceNotCenter:
		return Tr("Position your face inside the frame")
	case FaceVerifyFaceTooBig:
		return Tr("Keep away from the camera")
	case FaceVerifyFaceTooSmall:
		return Tr("Get closer to the camera")
	case FaceVerifyNoFace:
		return Tr("Face not found")
	case FaceVerifyTooManyFace:
		return Tr("Do not position multiple faces inside the frame")
	case FaceVerifyFaceNotClear:
		return Tr("Make sure the camera lens is clean")
	case FaceVerifyBrightness:
		return Tr("Do not enroll in dark, bright or backlit environments")
	case FaceVerifyFaceCovered:
		return Tr("Keep your face uncovered")
	}
	return Tr("Unknown error")
}

type FaceEnrollStatus int

const (
	FaceEnrollInvalid FaceVerifyStatus = iota - 1
	FaceEnrollSuccess
	FaceEnrollNotRealHuman
	FaceEnrollFaceNotCenter
	FaceEnrollFaceTooBig
	FaceEnrollFaceTooSmall
	FaceEnrollNoFace
	FaceEnrollTooManyFace
	FaceEnrollFaceNotClear
	FaceEnrollBrightness
	FaceEnrollFaceCovered
	FaceEnrollCancel
	FaceEnrollError
	FaceEnrollException
	FaceEnrollStatusCodeDisconnected       // 厂商断开连接
	FaceEnrollStatusCodeSenderDisconnected // 发起方断开连接
)
