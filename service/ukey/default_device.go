package ukey

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
)

type defaultConfig struct {
	DefaultDevice string
}

func writeToFile(filename string, serviceName string) error {
	if serviceName == "" || filename == "" {
		return errors.New("empty data")
	}

	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err != nil {
		logger.Warning(err)
		return err
	}

	config := defaultConfig{DefaultDevice: serviceName}

	data, err := json.Marshal(config)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, data, 0644)
}

func loadDefaultDeviceConfig(filename string) (*defaultConfig, error) {
	var config defaultConfig
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func removeConfigFile(file string) error {
	return os.Remove(file)
}
