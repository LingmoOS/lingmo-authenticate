package authcommon

type UKeyResType int

const (
	UKeyVerifyFailed UKeyResType = iota
	UKeyVerifySuccess
)

type UKeyResult struct {
	Result      UKeyResType `json:"result"`
	Description string      `json:"description"`
	Id          string      `json:"id"`
}

type UKeyState int

const (
	UKeyStateDeviceException UKeyState = iota
	UKeyStateDeviceOk
	UKeyStateDeviceVerifying
	UKeyStateDeviceNotExist
)

func (s UKeyState) String() string {
	if s == UKeyStateDeviceException {
		return Tr("Device abnormal")
	} else if s == UKeyStateDeviceOk {
		return Tr("Enter your PIN: ")
	} else if s == UKeyStateDeviceVerifying {
		return Tr("Verifying...")
	} else if s == UKeyStateDeviceNotExist {
		return Tr("UKey is required")
	} else {
		return Tr("Unknown UKey state")
	}
}
