package fingerprint

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/godbus/dbus"
)

const (
	interfacesDir = "/usr/share/deepin-authentication/interfaces/"
	configFile    = "/var/lib/deepin/authenticate/fingerprint.json"
)

type InterfaceConfig struct {
	Service     string `json:"service"`
	Path        string `json:"path"`
	Interface   string `json:"interface"`
	Type        int    `json:"type"`
	StorageType int    `json:"storage_type"`
}

const (
	InterfaceTypeFingerprint = 1
	InterfaceTypeFace        = 2

	InterfaceStorageTypeSelf        = 1 // 自助
	InterfaceStorageTypeTrusteeship = 2 // 托管
)

func getInterfaceConfigs(type0 int) ([]*InterfaceConfig, error) {
	fileInfoList, err := ioutil.ReadDir(interfacesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var result []*InterfaceConfig
	for _, fileInfo := range fileInfoList {
		filename := filepath.Join(interfacesDir, fileInfo.Name())
		var ifcCfg InterfaceConfig
		err := loadInterfaceConfig(filename, &ifcCfg)
		if err != nil {
			logger.Warning(err)
			continue
		}

		if !dbus.ObjectPath(ifcCfg.Path).IsValid() {
			logger.Warningf("interface config file %q, path %q is invalid", fileInfo.Name(), ifcCfg.Path)
			continue
		}

		if ifcCfg.Type == type0 {
			result = append(result, &ifcCfg)
		}
	}
	return result, nil
}

func loadInterfaceConfig(filename string, ifcCfg *InterfaceConfig) (err error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	err = json.Unmarshal(content, ifcCfg)
	return
}

type Config struct {
	DefaultDevice string
}

func loadConfig(filename string, cfg *Config) error {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	err = json.Unmarshal(content, cfg)
	return err
}

func saveConfig(filename string, cfg *Config) error {
	content, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(filename, content, 0644)
	return err
}
