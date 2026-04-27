package multifactor

import (
	"encoding/json"

	"pkg.deepin.io/dde/authentication/service/authcommon"
)

type AuthTypeConfig struct {
	Type    string
	Service string
}

type Config struct {
	ApplicationType         string
	RequestVerificationType []*AuthTypeConfig
}

const (
	authTypePassword          = "password"
	authTypeFingerprint       = "fingerprint"
	authTypeFace              = "face"
	authTypeActivateDirectory = "ad"
	authTypeUSBKey            = "ukey"
	authTypeIris              = "iris"
)

const (
	appTypeLogin         = "login"
	appTypeLock          = "lock"
	appTypeAuthorization = "authorization"
	appTypeOther         = "other"
	appTypeAll           = "all"
)

func AppTypeIntToAppTypeString(appType int) string {
	switch appType {
	case authcommon.AppTypeLogin:
		return appTypeLogin
	case authcommon.AppTypeLock:
		return appTypeLock
	case authcommon.AppTypeAuthorization:
		return appTypeAuthorization
	case authcommon.AppTypeOther:
		return appTypeOther
	}
	return appTypeAll
}

func appTypeStringToAppTypeInt(appType string) int {
	switch appType {
	case appTypeLogin:
		return authcommon.AppTypeLogin
	case appTypeLock:
		return authcommon.AppTypeLock
	case appTypeAuthorization:
		return authcommon.AppTypeAuthorization
	case appTypeOther:
		return authcommon.AppTypeOther
	}
	return 0
}

func mfaTypeToAuthFlag(type0 string) int {
	switch type0 {
	case authTypePassword:
		return authcommon.AuthenticationFlagPassword
	case authTypeFingerprint:
		return authcommon.AuthenticationFlagFingerprint
	case authTypeFace:
		return authcommon.AuthenticationFlagFace
	case authTypeActivateDirectory:
		return authcommon.AuthenticationFlagActiveDirectory
	case authTypeUSBKey:
		return authcommon.AuthenticationFlagUKey
	case authTypeIris:
		return authcommon.AuthenticationFlagIris
	}
	return 0
}

func AuthTypeToMfaType(type0 string) string {
	switch type0 {
	case authcommon.AuthTypePassword:
		return authTypePassword
	case authcommon.AuthTypeFingerprint:
		return authTypeFingerprint
	case authcommon.AuthTypeFace:
		return authTypeFace
	case authcommon.AuthTypeActiveDirectory:
		return authTypeActivateDirectory
	case authcommon.AuthTypeUKey:
		return authTypeUSBKey
	case authcommon.AuthTypeIris:
		return authTypeIris
	}
	return "Unknown"
}

func isSupportedAppType(type0 string) bool {
	switch type0 {
	case appTypeLogin:
		return true
	case appTypeLock:
		return true
	case appTypeAuthorization:
		return true
	case appTypeOther:
		return true
	case appTypeAll:
		return true
	}
	return false
}

func isSupportedAuthType(type0 string) bool {
	switch type0 {
	case authTypePassword:
		return true
	case authTypeFingerprint:
		return true
	case authTypeFace:
		return true
	case authTypeActivateDirectory:
		return true
	case authTypeUSBKey:
		return true
	case authTypeIris:
		return true
	}
	return false
}

func toConfigObject(b []byte) (*Config, error) {
	var c Config

	err := json.Unmarshal(b, &c)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (atc *AuthTypeConfig) IsUseDefaultService() bool {
	if atc.Service == "" || atc.Service == "*" {
		return true
	} else {
		return false
	}
}

func (c *Config) GetAuthTypeConfig(type0 string) *AuthTypeConfig {
	for _, atc := range c.RequestVerificationType {
		if atc.Type == AuthTypeToMfaType(type0) {
			return atc
		}
	}
	return nil
}

func (c *Config) IsUseDefaultService(type0 string) bool {
	atc := c.GetAuthTypeConfig(type0)
	if atc != nil {
		return atc.IsUseDefaultService()
	}
	return false
}

func (c *Config) isAllTypeConfig() bool {
	return c.ApplicationType == appTypeAll
}

func (c *Config) isValidConfig() bool {
	if len(c.RequestVerificationType) <= 0 {
		return false
	}

	if !isSupportedAppType(c.ApplicationType) {
		// 在配置文件中, '*' 代表所有类型
		if c.ApplicationType == "*" {
		} else {
			return false
		}
	}

	mapTmp := make(map[string]bool)
	// check if type valid
	for _, atc := range c.RequestVerificationType {
		if !isSupportedAuthType(atc.Type) {
			return false
		}

		//check if type repeat
		if _, ok := mapTmp[atc.Type]; ok {
			return false
		}
		mapTmp[atc.Type] = true
	}

	return true
}

func (c *Config) IsSingleType() bool {
	if len(c.RequestVerificationType) == 1 {
		return true
	}
	return false
}
