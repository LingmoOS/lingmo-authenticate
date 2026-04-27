package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	appTypeListFilePath = "/usr/share/deepin-authentication/app-type-list"
)

type AppConfig struct {
	App  string `json:"app"`
	Type string `json:"type"`
}

type AppTypeConfig struct {
	AppType []AppConfig `json:"app-type"`
}

func loadConfig() *AppTypeConfig {
	bytes, err := ioutil.ReadFile(appTypeListFilePath)
	if err != nil {
		return nil
	}

	var cfg AppTypeConfig
	err = json.Unmarshal(bytes, &cfg)
	if err != nil {
		return nil
	}
	return &cfg
}

func (a AppTypeConfig) dumpToFile() error {
	bytes, err := json.Marshal(a)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(appTypeListFilePath, bytes, 0644)
}

var app = flag.String("a", "", "the executable path of application. eg: /usr/bin/sudo")
var type0 = flag.String("t", "", "the type of authentication initiated by the application. include login, lock, authorization and other.")

func isSupportedAppType(type0 string) bool {
	switch type0 {
	case "login":
		return true
	case "lock":
		return true
	case "authorization":
		return true
	case "other":
		return true
	}
	return false
}

func main() {
	flag.Parse()

	if len(os.Args) != 5 {
		fmt.Println(len(os.Args))
		flag.CommandLine.Usage()
		return
	}

	if *app == "" || *type0 == "" {
		flag.CommandLine.Usage()
		return
	}

	if !isSupportedAppType(*type0) {
		fmt.Printf("type %s is not supported", *type0)
		return
	}
	configs := loadConfig()

	// 去重
	for id, conf := range configs.AppType {
		if conf.App == *app {
			configs.AppType = append(configs.AppType[:id], configs.AppType[id+1:]...)
			fmt.Printf("%s's configuration will be covered.\n", conf.App)
		}
	}
	configs.AppType = append(configs.AppType, AppConfig{Type: *type0, App: *app})

	err := configs.dumpToFile()
	if err != nil {
		fmt.Println(err)
	}
}
