package authcommon

import (
	"github.com/godbus/dbus"
)

const (
	AllAuthenticationTypeMask = AuthenticationFlagPassword |
		AuthenticationFlagFingerprint |
		AuthenticationFlagFace |
		AuthenticationFlagActiveDirectory |
		AuthenticationFlagUKey |
		AuthenticationFlagIris |
		AuthenticationFlagCustom
)

const (
	AuthenticationFlagPassword        = 1 << iota // 启用密码认证
	AuthenticationFlagFingerprint                 // 启用指纹认证
	AuthenticationFlagFace                        // 启用人脸认证
	AuthenticationFlagActiveDirectory             // 启用 AD 域认证
	AuthenticationFlagUKey                        // 启用 UKey 认证
	AuthenticationFlagFingerVein                  // 指静脉
	AuthenticationFlagIris                        // 虹膜
	AuthenticationFlagCustom          = 1 << 30   // 自定义插件认证，放最后，int32第31位
)

const AllAuthenticationFlag = -1

var AllAuthTypes = []string{
	AuthTypePassword,
	AuthTypeActiveDirectory,
	AuthTypeFingerprint,
	AuthTypeFace,
	AuthTypeUKey,
	AuthTypeIris,
	AuthTypeCustom,
}

const (
	AuthTypePassword        = "password"
	AuthTypeFingerprint     = "fingerprint"
	AuthTypeFace            = "face"
	AuthTypeActiveDirectory = "active directory"
	AuthTypeUKey            = "usb key"
	AuthTypeFingerVein      = "finger vein"
	AuthTypeIris            = "iris"
	AuthTypeCustom          = "custom"
)

type Chara string

type ActionId string

type UUID string

type CharaType int32

type ActionType int32

type LimitType string

type CodeStatusInfo struct {
	ActionId ActionId
	Sender   dbus.Sender
	Code     StatusCode
	Msg      string
}
type DriverInfo struct {
	DriverName string
	CharaType  CharaType
}
type CharaInfo struct {
	ServerName string    `json:"ServerName"`
	Uuid       UUID      `json:"Uuid"`
	CharaType  CharaType `json:"CharaType"`
	CharaName  string    `json:"CharaName"`
	Chara      Chara     `json:"Chara"`
	BAvailable bool      `json:"BAvailable"`
	Time       int64     `json:"Time"`
}

type StatusCode int32

const (
	Eroll ActionType = iota
	Verify
)

const (
	Local  LimitType = "Local"
	Remote LimitType = "Remote"
)

func IsBiometricAuth(type0 string) bool {
	if type0 == AuthTypeFingerprint || type0 == AuthTypeFingerVein || type0 == AuthTypeFace || type0 == AuthTypeIris {
		return true
	}
	return false
}

func AuthTypeToFlag(type0 string) int {
	switch type0 {
	case AuthTypePassword:
		return AuthenticationFlagPassword

	case AuthTypeFingerprint:
		return AuthenticationFlagFingerprint

	case AuthTypeFace:
		return AuthenticationFlagFace

	case AuthTypeActiveDirectory:
		return AuthenticationFlagActiveDirectory

	case AuthTypeUKey:
		return AuthenticationFlagUKey

	case AuthTypeFingerVein:
		return AuthenticationFlagFingerVein

	case AuthTypeIris:
		return AuthenticationFlagIris

	case AuthTypeCustom:
		return AuthenticationFlagCustom

	default:
		return 0
	}
}

func AuthFlagToType(type0 int) string {
	switch type0 {
	case AuthenticationFlagPassword:
		return AuthTypePassword

	case AuthenticationFlagFingerprint:
		return AuthTypeFingerprint

	case AuthenticationFlagFace:
		return AuthTypeFace

	case AuthenticationFlagActiveDirectory:
		return AuthTypeActiveDirectory

	case AuthenticationFlagUKey:
		return AuthTypeUKey

	case AuthenticationFlagFingerVein:
		return AuthTypeFingerVein

	case AuthenticationFlagIris:
		return AuthTypeIris

	case AuthenticationFlagCustom:
		return AuthTypeCustom

	case AllAuthenticationFlag:
		return "All"

	default:
		return "unknown"
	}
}

const (
	InputTypeKeyboard = 1 << iota
	InputTypeFinger
	InputTypeCameraFace
	InputTypeCameraIris
	InputTypeCustom
)

func AuthTypeToInputType(type0 string) int {
	switch type0 {
	case AuthTypePassword, AuthTypeUKey, AuthTypeActiveDirectory:
		return InputTypeKeyboard

	case AuthTypeFingerprint, AuthTypeFingerVein:
		return InputTypeFinger

	case AuthTypeFace:
		return InputTypeCameraFace

	case AuthTypeIris:
		return InputTypeCameraIris

	case AuthTypeCustom:
		return InputTypeCustom

	default:
		return InputTypeKeyboard
	}
}

func AuthTypeToPriority(type0 string) int {
	var offset int = 1
	switch type0 {
	case AuthTypePassword:
		return offset + 7

	case AuthTypeActiveDirectory:
		return offset + 6

	case AuthTypeUKey:
		return offset + 5

	case AuthTypeFingerprint:
		return offset + 4

	case AuthTypeFingerVein:
		return offset + 3

	case AuthTypeFace:
		return offset + 2

	case AuthTypeIris:
		return offset + 1

	case AuthTypeCustom:
		return offset + 0

	default:
		return int(^uint(0) >> 1)
	}
}

const (
	AppTypeLogin = iota + 1
	AppTypeLock
	AppTypeAuthorization
	AppTypeOther
)

func IsSupportedType(appType int) bool {
	switch appType {
	case AppTypeLogin:
		return true
	case AppTypeLock:
		return true
	case AppTypeAuthorization:
		return true
	case AppTypeOther:
		return true
	}
	return false
}
