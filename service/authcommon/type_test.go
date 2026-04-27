package authcommon

import (
	"strconv"
	"testing"
)

func TestAuthType(t *testing.T) {
	var offset int = 1
	tests := []struct {
		aythType        string
		isBiometricAuth bool
		inputType       int
		priority        int
		flag            int
	}{
		{
			aythType:        AuthTypePassword,
			isBiometricAuth: false,
			inputType:       InputTypeKeyboard,
			priority:        offset + 7,
			flag:            AuthenticationFlagPassword,
		},
		{
			aythType:        AuthTypeActiveDirectory,
			isBiometricAuth: false,
			inputType:       InputTypeKeyboard,
			priority:        offset + 6,
			flag:            AuthenticationFlagActiveDirectory,
		},
		{
			aythType:        AuthTypeUKey,
			isBiometricAuth: false,
			inputType:       InputTypeKeyboard,
			priority:        offset + 5,
			flag:            AuthenticationFlagUKey,
		},
		{
			aythType:        AuthTypeFingerprint,
			isBiometricAuth: true,
			inputType:       InputTypeFinger,
			priority:        offset + 4,
			flag:            AuthenticationFlagFingerprint,
		},
		{
			aythType:        AuthTypeFingerVein,
			isBiometricAuth: true,
			inputType:       InputTypeFinger,
			priority:        offset + 3,
			flag:            AuthenticationFlagFingerVein,
		},
		{
			aythType:        AuthTypeFace,
			isBiometricAuth: true,
			inputType:       InputTypeCameraFace,
			priority:        offset + 2,
			flag:            AuthenticationFlagFace,
		},
		{
			aythType:        AuthTypeIris,
			isBiometricAuth: true,
			inputType:       InputTypeCameraIris,
			priority:        offset + 1,
			flag:            AuthenticationFlagIris,
		},
		{
			aythType:        AuthTypeCustom,
			isBiometricAuth: false,
			inputType:       InputTypeCustom,
			priority:        offset + 0,
			flag:            AuthenticationFlagCustom,
		},
		{
			aythType:        "default",
			isBiometricAuth: false,
			inputType:       InputTypeKeyboard,
			priority:        int(^uint(0) >> 1),
			flag:            0,
		},
	}
	for _, tt := range tests {
		t.Run("TestAuthType"+tt.aythType, func(t *testing.T) {
			isBiometricAuth := IsBiometricAuth(tt.aythType)
			if isBiometricAuth != tt.isBiometricAuth {
				t.Error("Test IsBiometricAuth error,AuthType=", tt.aythType)
				return
			}
			inputType := AuthTypeToInputType(tt.aythType)
			if inputType != tt.inputType {
				t.Error("Test AuthTypeToInputType error,AuthType=", tt.aythType)
				return
			}
			priority := AuthTypeToPriority(tt.aythType)
			if priority != tt.priority {
				t.Error("Test AuthTypeToPriority error,AuthType=", tt.aythType)
				return
			}
			flag := AuthTypeToFlag(tt.aythType)
			if flag != tt.flag {
				t.Error("Test AuthTypeToFlag error,AuthType=", tt.aythType)
				return
			}
		})
	}
}

func TestAuthFlagToType(t *testing.T) {
	tests := []struct {
		aythType string
		flag     int
	}{
		{
			aythType: AuthTypePassword,
			flag:     AuthenticationFlagPassword,
		},
		{
			aythType: AuthTypeFingerprint,
			flag:     AuthenticationFlagFingerprint,
		},
		{
			aythType: AuthTypeFace,
			flag:     AuthenticationFlagFace,
		},
		{
			aythType: AuthTypeActiveDirectory,
			flag:     AuthenticationFlagActiveDirectory,
		},
		{
			aythType: AuthTypeUKey,
			flag:     AuthenticationFlagUKey,
		},
		{
			aythType: AuthTypeFingerVein,
			flag:     AuthenticationFlagFingerVein,
		},
		{
			aythType: AuthTypeIris,
			flag:     AuthenticationFlagIris,
		},
		{
			aythType: "All",
			flag:     AllAuthenticationFlag,
		},
		{
			aythType: "unknown",
			flag:     -12345,
		},
	}
	for i, tt := range tests {
		t.Run("AuthType"+strconv.Itoa(i), func(t *testing.T) {
			authType := AuthFlagToType(tt.flag)
			if authType != tt.aythType {
				t.Error("TestAuthFlagToType error,flag=", tt.flag)
				return
			}
		})
	}
}

func TestIsSupportedType(t *testing.T) {
	tests := []int{AppTypeLogin, AppTypeLock, AppTypeAuthorization, AppTypeOther}
	for i, tt := range tests {
		t.Run("TestIsSupportedType"+strconv.Itoa(i), func(t *testing.T) {
			isSupported := IsSupportedType(tt)
			if !isSupported {
				t.Error("TestIsSupportedType error,appType=", tt)
				return
			}
		})
	}
}
