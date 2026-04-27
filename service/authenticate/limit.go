package authenticate

import (
	"encoding/json"
	"io/ioutil"
	"strconv"
	"strings"
	"time"

	"github.com/linuxdeepin/go-lib/keyfile"
	"github.com/linuxdeepin/go-lib/utils"
	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

const (
	configFile                       = "/var/lib/deepin/authenticate/config_v1.json"
	limitStatesV1File                = "/var/lib/deepin/authenticate/limit-states_v1.json"
	limitStatesFile                  = "/var/lib/deepin/authenticate/limit-states.json"
	sessionShellLimitConfigFile      = "/usr/share/dde-session-shell/dde-session-shell.conf"
	sessionShellKeyFileSection       = "LockTime"
	sessionShellKeyFileKeyMaxTries   = "lockLimitTryNum"
	sessionShellKeyFileKeyUnlockSecs = "lockWaitTime"
)

type Config struct {
	Limits []*LimitConfig
}

func loadSessionShellLimitConfig() *LimitConfig {
	file := keyfile.NewKeyFile()
	err := file.LoadFromFile(sessionShellLimitConfigFile)
	if err != nil {
		logger.Warning(err)
		return nil
	}

	_, err = file.GetSection(sessionShellKeyFileSection)
	if err != nil {
		logger.Warning(err)
		return nil
	}

	passwordConfig := &LimitConfig{
		Type:                   "password",
		UnlockSecs:             0,
		MaxTries:               0,
		DynamicLimit:           false,
		DynamicLimitUnlockSecs: nil,
	}

	maxTries, err := file.GetInt(sessionShellKeyFileSection, sessionShellKeyFileKeyMaxTries)
	if err != nil {
		logger.Warning(err)
		return nil
	}

	strUnlockSecs, err := file.GetString(sessionShellKeyFileSection, sessionShellKeyFileKeyUnlockSecs)
	if err != nil {
		logger.Warning(err)
		return nil
	}
	logger.Debugf("get key %s's value: %v", sessionShellKeyFileKeyUnlockSecs, strUnlockSecs)

	// session-shell 文件中获取到的时间为 "3,5,15,60,1440" 格式,且单位为分钟,需要转换为秒
	strUnlockSecs = strings.Replace(strUnlockSecs, "\"", "", -1)
	strUnlockSecsSlice := strings.Split(strUnlockSecs, ",")
	var intUnlockSecs []int

	for _, str := range strUnlockSecsSlice {
		val, err := strconv.Atoi(str)
		if err != nil {
			logger.Warning(err)
			return nil
		}
		val *= 60
		intUnlockSecs = append(intUnlockSecs, val)
	}

	passwordConfig.MaxTries = maxTries
	passwordConfig.DynamicLimitUnlockSecs = intUnlockSecs
	passwordConfig.DynamicLimit = true
	return passwordConfig
}

func loadConfig(filename string, cfg *Config) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, cfg)
	if err != nil {
		logger.Warningf("unmarshal file %s err: %v", filename, err)
		return err
	}

	// 兼容方案,如果 session-shell 的配置文件存在,则更新 password 的配置为 session-shell 中的配置
	passwordConfig := loadSessionShellLimitConfig()
	// 如果读到了 session-shell 的配置，并且之前有 password 的配置，则更新 password 的配置为 session-shell 的配置，
	// 如果之前没有 password 的配置，则直接添加 session-shell 的配置
	if passwordConfig != nil {
		var updated bool
		for _, limitConfig := range cfg.Limits {
			if limitConfig.Type == "password" {
				*limitConfig = *passwordConfig
				updated = true
				break
			}
		}
		if !updated {
			cfg.Limits = append(cfg.Limits, passwordConfig)
		}
		logger.Debugf("password limit config updated: %v", passwordConfig)
	}

	// 修正配置
	// 当 MaxTries < 0 时，修正为 0，不限制。
	for _, limitConfig := range cfg.Limits {
		if limitConfig.MaxTries < 0 {
			limitConfig.MaxTries = 0
		}
	}
	return nil
}

type LimitConfig struct {
	Type                   string
	UnlockSecs             int   // 超出认证失败次数后，解除锁定需要等待的时间（秒数），如果 <0 则永久锁定。
	MaxTries               int   // 认证失败几次后拒绝, 如果 == 0 则不限制
	DynamicLimit           bool  // 是否是动态锁定
	DynamicLimitUnlockSecs []int // 动态锁定时间,可随次数变化,次数起始为 MaxTries ,第一个元素x含义为,失败 MaxTries 之后,锁定 x 秒
}

type LimitState struct {
	Type        string
	NumFailures int
	LockAt      time.Time
}

type LimitForExport struct {
	Type string `json:"type"`
	Flag int    `json:"flag"`

	UnlockSecs int `json:"unlockSecs"`
	MaxTries   int `json:"maxTries"`

	NumFailures int       `json:"numFailures"`
	Locked      bool      `json:"locked"`
	UnlockTime  time.Time `json:"unlockTime"`
}

func loadV1LimitStates(filename string, states *map[LimitType]map[string][]LimitState) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, states)
	return err
}
func loadLimitStates(filename string, states *map[string][]LimitState) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}
	err = json.Unmarshal(data, states)
	return err
}

func saveLimitStates(states map[LimitType]map[string][]LimitState) error {
	data, err := json.Marshal(states)
	if err != nil {
		return err
	}
	err = utils.SyncWriteFile(limitStatesV1File, data, 0644)
	if err != nil {
		return err
	}
	// 将数据写入老版本limitstate
	data, err = json.Marshal(states[Local])
	if err != nil {
		logger.Warning(err)
	}
	err = utils.SyncWriteFile(limitStatesFile, data, 0644)
	if err != nil {
		logger.Warning(err)
	}
	return nil
}

type limit struct {
	type0                  string
	flag                   int
	numFailures            int
	lockAt                 time.Time
	lastFailAt             time.Time // 最后一次失败的时间，暂时无用
	unlockSecs             int
	maxTries               int
	dynamicLimit           bool
	dynamicLimitUnlockSecs []int
}

func (l *limit) tryReset(now time.Time) {
	if l.unlockSecs < 0 {
		// 不能自动解锁
		return
	}
	if l.numFailures >= l.maxTries && l.maxTries > 0 {
		unlockDuration := time.Second * time.Duration(l.unlockSecs)
		// go 的 Sub 方法只是简单的将 单调时间 进行运算，而在待机时 单调时间 不会变化，导致时间运算出问题
		lockAtUn := l.lockAt.UnixNano()
		nowUn := now.UnixNano()
		if time.Duration(nowUn-lockAtUn) > unlockDuration {
			// 可以重置了
			logger.Debugf("reset type %s", l.type0)
			//重置解锁时间,但错误次数不重置
			l.reset()
		}
	}
}

func (l *limit) reset() {
	l.lockAt = time.Time{}
	// 如果支持根据错误次数设置动态锁定时间,则只能重置解锁时间,不能重置次数
	if l.dynamicLimit {
		l.unlockSecs = 0
	} else {
		l.numFailures = 0
	}
}

func (l *limit) allow(now time.Time) (bool, time.Time) {
	if l.maxTries == 0 {
		// 不受限制
		return true, time.Time{}
	}
	//logger.Debugf("l: %#v", l)

	if l.dynamicLimit {
		l.unlockSecs = l.getDynamicLimitTime()
	}

	logger.Debugf("type %s, current fail times: %d, unlockSecs time is: %d", l.type0, l.numFailures, l.unlockSecs)
	l.tryReset(now)
	if l.numFailures < l.maxTries {
		return true, time.Time{}
	}
	if l.unlockSecs == 0 {
		return true, time.Time{}
	}
	unlockDuration := time.Second * time.Duration(l.unlockSecs)
	return false, l.lockAt.Add(unlockDuration)
}

func (l *limit) fail(now time.Time) {
	if l.maxTries == 0 {
		return
	}
	l.tryReset(now)
	l.lastFailAt = now
	l.numFailures++
	if l.numFailures >= l.maxTries {
		l.lockAt = now
	}
}

func (l *limit) getDynamicLimitTime() int {

	failNum := l.numFailures - l.maxTries
	if failNum < 0 {
		return 0
	}

	if failNum >= len(l.dynamicLimitUnlockSecs) {
		return l.dynamicLimitUnlockSecs[len(l.dynamicLimitUnlockSecs)-1]
	}

	return l.dynamicLimitUnlockSecs[failNum]
}
