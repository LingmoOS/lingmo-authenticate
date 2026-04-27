package authcommon

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/linuxdeepin/go-lib/log"

	"github.com/godbus/dbus"
)

const InterfacesDir = "/usr/share/deepin-authentication/interfaces/"

type ResType int

const (
	ResDefault ResType = iota
	ResSuccess
	ResFailed
)

type VerifyProcess int

const (
	Verifying VerifyProcess = iota
	VerifySuccess
	VerifyFailed
)

const (
	InterfaceTypeFingerprint = 1
	InterfaceTypeUKey        = 2
	InterfaceTypeFace        = 4
	InterfaceTypeIris        = 64

	InterfaceStorageTypeSelf        = 1 // 自助
	InterfaceStorageTypeTrusteeship = 2 // 托管
)

type InterfaceConfig struct {
	Service     string `json:"service"`
	Path        string `json:"path"`
	Interface   string `json:"interface"`
	Type        int    `json:"type"`
	StorageType int    `json:"storage_type"`
}

type InterfaceConfigWithFileName struct {
	*InterfaceConfig
	FileName string
}

var logger = log.NewLogger("deepin-authenticate/authcommon")

func GetInterfaceConfigs(dir string, type0 int) ([]*InterfaceConfigWithFileName, error) {
	fileInfoList, err := ioutil.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var result []*InterfaceConfigWithFileName
	for _, fileInfo := range fileInfoList {
		filename := filepath.Join(dir, fileInfo.Name())
		config, err := LoadInterfaceConfig(filename, type0)
		configWithFileName := InterfaceConfigWithFileName{
			InterfaceConfig: config,
			FileName:        filename,
		}
		if err == nil {
			result = append(result, &configWithFileName)
		} else {
			logger.Warning(err)
		}
	}
	return result, nil
}

func LoadInterfaceConfig(filename string, type0 int) (*InterfaceConfig, error) {
	ifcCfg := InterfaceConfig{}
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(content, &ifcCfg)

	if type0 != ifcCfg.Type {
		return nil, fmt.Errorf("expect type %d not matched with %d", type0, ifcCfg.Type)
	}
	if !dbus.ObjectPath(ifcCfg.Path).IsValid() {
		return nil, fmt.Errorf("interface config file %q, path %q is invalid", filename, ifcCfg.Path)
	}

	return &ifcCfg, nil
}
