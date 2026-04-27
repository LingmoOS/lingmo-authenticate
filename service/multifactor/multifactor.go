package multifactor

import (
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/linuxdeepin/go-lib/strv"

	"github.com/fsnotify/fsnotify"
	"github.com/linuxdeepin/go-lib/log"
	"github.com/linuxdeepin/go-lib/utils"

	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

var logger = log.NewLogger("deepin-authenticate/authenticate")

const (
	multiFactorConfigFileDir = "/usr/share/deepin-authentication/mfa-conf.d/"
)

var MfConfig *MFAConfig

func GetMFAObj() *MFAConfig {
	return MfConfig
}

func Init() {
	MfConfig = newMultiFactor()
	MfConfig.init()
}

type configWithPriority struct {
	*Config
	priority int
}

type mfaFileInfo struct {
	filename string
	priority int
	appType  string
}

type MFAConfig struct {
	configs      map[string]*configWithPriority
	watcher      *fsnotify.Watcher
	disabledList []string
}

func newMultiFactor() *MFAConfig {
	return &MFAConfig{configs: make(map[string]*configWithPriority)}
}

func (m *MFAConfig) init() {
	m.loadConfigs(multiFactorConfigFileDir)
	m.initWatcher()
	disableLines, err := ReadFileLines(forceDisableFilePath)
	if err == nil {
		m.disabledList = disableLines
		logger.Debug(m.disabledList)
	}
}

func (m *MFAConfig) initWatcher() {
	var err error
	m.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		logger.Warning(err)
	}
	err = m.watcher.Add(multiFactorConfigFileDir)
	if err != nil {
		logger.Warningf("when monitor %s err: %s", multiFactorConfigFileDir, err)
	}

	go m.dirEventHandler()
}

func (m *MFAConfig) dirEventHandler() {
	for {
		select {
		case ev := <-m.watcher.Events:
			logger.Debugf("file %s changed %d", ev.Name, ev.Op)

			if ev.Op&fsnotify.Create != 0 || ev.Op&fsnotify.Write != 0 {
				m.loadConfigFile(ev.Name)
			}
			if ev.Op&fsnotify.Remove != 0 {
				m.removeConfig(ev.Name)
			}
		case err := <-m.watcher.Errors:
			logger.Warning("receive file watcher error:", err)
		}
	}
}

func (m *MFAConfig) loadConfigFile(file string) {
	fileName := path.Base(file)
	b, err := ioutil.ReadFile(file)
	if err != nil {
		logger.Warningf("read %s err: %s", fileName, err)
		return
	}

	c, err := toConfigObject(b)
	if err != nil {
		logger.Warningf("file %s err: %s", fileName, err)
		return
	}

	fileInfo, err := m.resolveFilename(fileName)
	if err != nil {
		logger.Warningf("file %s err: %s", fileName, err)
		return
	}

	if c.isValidConfig() {
		// 检查配置文件与文件内容是否匹配
		if fileInfo.appType != c.ApplicationType {
			if !(fileInfo.appType == appTypeAll && c.ApplicationType == "*") {
				logger.Warningf("filename %s with file context is not match", fileName)
				return
			}
		}

		logger.Debugf("file %s's multi factor config is valid", fileName)
		if val, ok := m.configs[fileInfo.appType]; ok {
			if val.priority < fileInfo.priority {
				m.configs[fileInfo.appType] = &configWithPriority{Config: c, priority: fileInfo.priority}
				logger.Debugf("file %s's priority is higher", fileName)
			}
		} else {
			m.configs[fileInfo.appType] = &configWithPriority{Config: c, priority: fileInfo.priority}
		}
	} else {
		logger.Warningf("config file %s is invalid", fileName)
	}
}

func (m *MFAConfig) removeConfig(fileName string) {
	delete(m.configs, filepath.Base(fileName))
}

func (m *MFAConfig) loadConfigs(dir string) {
	files, err := utils.GetFilesInDir(dir)
	if err != nil {
		logger.Warning(err)
	}

	for _, f := range files {
		m.loadConfigFile(f)
	}
}

func (m *MFAConfig) IsProgramConfigured(appType int) bool {
	return m.GetConfig(appType) != nil
}

func (m *MFAConfig) GetConfig(appType int) *Config {
	for _, c := range m.configs {
		if appTypeStringToAppTypeInt(c.ApplicationType) == appType {
			return c.Config
		}
	}

	if val, ok := m.configs[appTypeAll]; ok {
		return val.Config
	}

	return nil
}

func (m *MFAConfig) IsProgramEnabled(execPath string) bool {
	return !strv.Strv(m.disabledList).Contains(execPath)
}

func GetAuthTypeList(c *Config) []int {
	var list []int
	for _, atc := range c.RequestVerificationType {
		list = append(list, mfaTypeToAuthFlag(atc.Type))
	}
	return list
}

func (m *MFAConfig) resolveFilename(filename string) (*mfaFileInfo, error) {
	filenameSlice := strings.Split(filename, "-")
	if len(filenameSlice) != 3 {
		return nil, fmt.Errorf("filename %s format invalid", filename)
	}

	if !isSupportedAppType(filenameSlice[1]) {
		return nil, fmt.Errorf("filename %s format invalid", filename)
	}

	split := strings.Split(filenameSlice[2], ".")
	if len(split) != 2 {
		return nil, fmt.Errorf("filename %s format invalid", filename)
	}
	priority, err := strconv.Atoi(split[0])
	if err != nil {
		return nil, err
	}

	return &mfaFileInfo{filename: filename, appType: filenameSlice[1], priority: priority}, nil
}
