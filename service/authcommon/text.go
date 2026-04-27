package authcommon

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/linuxdeepin/go-lib/gettext"
)

const (
	envLangField         = "LANG"
	envLanguageField     = "LANGUAGE"
	userLocaleFilePath   = ".config/locale.conf"
	systemLocaleFilePath = "/etc/default/locale"
)

func Password() string {
	return Tr("Password")
}

func FirstUpper(data string) string {
	bytes := []byte(data)
	if bytes[0] >= 'a' && bytes[0] <= 'z' {
		bytes[0] -= 32
	}
	return string(bytes)
}

func SliceFirstDataCharUpper(data []string) []string {
	if len(data) == 0 {
		return data
	}

	data[0] = FirstUpper(data[0])
	return data
}

func PINDeal() string {
	return Tr("Enter your PIN")
}

type langConfig struct {
	lang     string
	language string
	filename string
}

var (
	_fsWatcher     *fsnotify.Watcher
	_langConfigMap map[string]*langConfig = make(map[string]*langConfig)
	_once          sync.Once
	_langMux       sync.Mutex
)

func Tr(msg string) string {
	return msg
}

// 临时设置用户语言,获取翻译文案
func TranslateWrapper(username string, shouldSkip bool, format string, msg ...string) string {
	if shouldSkip {
		var translateMsg []interface{}
		for _, m := range msg {
			translateMsg = append(translateMsg, m)
		}
		return fmt.Sprintf(format, translateMsg...)
	}

	config, err := getLanguageConfig(username)

	_langMux.Lock()
	defer _langMux.Unlock()

	oldLang := os.Getenv(envLangField)
	oldLanguage := os.Getenv(envLanguageField)

	if err == nil {
		os.Setenv(envLangField, config.lang)
		os.Setenv(envLanguageField, config.language)
		// 调用 InitI18n 后才能生效
		gettext.InitI18n()
	}

	var translateMsg []interface{}
	for _, m := range msg {
		translateMsg = append(translateMsg, gettext.Tr(m))
	}

	trMsg := fmt.Sprintf(gettext.Tr(format), translateMsg...)

	os.Setenv(envLangField, oldLang)
	os.Setenv(envLanguageField, oldLanguage)
	gettext.InitI18n()
	return trMsg
}

// 先从map中获取,如果获取不到,则去对应用户文件中获取
// 若获取不到,则读取系统默认语言配置
// 以上成功获取的配置文件,均会被添加到fsnotify中被监听,若配置文件有改动则为配置更新过了,需要重新获取
func getLanguageConfig(username string) (*langConfig, error) {

	if config, ok := _langConfigMap[username]; ok {
		return config, nil
	}

	_once.Do(func() {
		_fsWatcher, _ = fsnotify.NewWatcher()
		go fsWatchDispatcher()
	})

	var config *langConfig
	var file string
	info, err := GetUserInfo(username)
	if info != nil {
		file = filepath.Join(info.HomeDir, userLocaleFilePath)
		config = loadConfigFile(file)

		if config != nil {

			_langMux.Lock()
			_langConfigMap[username] = config
			_langMux.Unlock()

			err = _fsWatcher.Add(file)
			if err != nil {
				logger.Warning(err)
			}
		}
	}

	if config == nil {
		file = systemLocaleFilePath
		config = loadConfigFile(file)
		if config == nil {
			return nil, fmt.Errorf("can not find configuration")
		}
	}
	return config, nil
}

func parseAndUpdateConfig(data []byte) *langConfig {
	lines := strings.Split(string(data), "\n")
	if len(lines) < 2 {
		return nil
	}

	var keyFileMap map[string]string = make(map[string]string)

	for _, line := range lines {
		data := strings.Split(line, "=")
		if len(data) < 2 {
			continue
		}
		keyFileMap[data[0]] = data[1]
	}

	if keyFileMap[envLangField] == "" && keyFileMap[envLanguageField] == "" {
		return nil
	}
	return &langConfig{lang: keyFileMap[envLangField], language: keyFileMap[envLanguageField]}
}

func loadConfigFile(filename string) *langConfig {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.Warning(err)
		return nil
	}
	config := parseAndUpdateConfig(data)
	if config == nil {
		return nil
	}
	config.filename = filename
	return config
}

func updateConfig(filename string) {
	for username, config := range _langConfigMap {
		if config.filename == filename {
			delete(_langConfigMap, username)
		}
	}
}

func fsWatchDispatcher() {
	for {
		select {
		case ev := <-_fsWatcher.Events:
			logger.Debugf("file %s changed %s", ev.Name, ev.Op)

			if ev.Op&fsnotify.Write != 0 || ev.Op&fsnotify.Remove != 0 {
				updateConfig(ev.Name)
			}
		case err := <-_fsWatcher.Errors:
			logger.Warning("receive file watcher error:", err)
		}
	}

}
