package fingerprint

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/linuxdeepin/go-lib/strv"

	"github.com/godbus/dbus"
	fprintd "github.com/linuxdeepin/go-dbus-factory/net.reactivated.fprint"
	pkgfp "pkg.deepin.io/dde/authentication/pkg/fingerprint"
)

const (
	fprintdEnrollStatusCompleted          = "enroll-completed"
	fprintdEnrollStatusFailed             = "enroll-failed"
	fprintdEnrollStatusStagePassed        = "enroll-stage-passed"
	fprintdEnrollStatusRetryScan          = "enroll-retry-scan"
	fprintdEnrollStatusSwipeTooShort      = "enroll-swipe-too-short"
	fprintdEnrollStatusFingerNotCentered  = "enroll-finger-not-centered"
	fprintdEnrollStatusRemoveAndRetry     = "enroll-remove-and-retry"
	fprintdEnrollStatusDataFull           = "enroll-data-full"
	fprintdEnrollStatusEnrollDisconnected = "enroll-disconnected"
	fprintdEnrollStatusEnrollUnknownError = "enroll-unknown-error"

	fprintdVerifyStatusNoMatch           = "verify-no-match"
	fprintdVerifyStatusMatch             = "verify-match"
	fprintdVerifyStatusRetryScan         = "verify-retry-scan"
	fprintdVerifyStatusSwipeTooShort     = "verify-swipe-too-short"
	fprintdVerifyStatusFingerNotCentered = "verify-finger-not-centered"
	fprintdVerifyStatusRemoveAndRetry    = "verify-remove-and-retry"
	fprintdVerifyStatusDisconnected      = "verify-disconnected"
	fprintdVerifyStatusUnknownError      = "verify-unknown-error"

	fprintdNameMapConfigDir = "/var/lib/dde-daemon/fingerprint/fprint/"
)

type FingerNameConfig struct {
	filename string
	data     struct {
		StdNames  []string
		FingerMap map[string]string
	}
}

type FprintdDevice struct {
	baseDevice
	core fprintd.Device

	curEnrollFinger struct {
		stdName    string
		fingerName string
	}
}

func newFprintdDevice(m *Manager, objPath dbus.ObjectPath) (*FprintdDevice, error) {
	sysBus, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	core, err := fprintd.NewDevice(sysBus, objPath)
	if err != nil {
		return nil, err
	}
	d := &FprintdDevice{core: core}
	d.m = m
	d.claimFn = d.doClaim
	return d, nil
}

func (d *FprintdDevice) select0() {
	d.listenSignals()
}

func (d *FprintdDevice) deselect() {
	d.core.RemoveAllHandlers()
}

func (d *FprintdDevice) listenSignals() {
	d.core.InitSignalExt(d.m.sysSigLoop, true)
	_, err := d.core.ConnectEnrollStatus(func(result string, done bool) {
		var code int
		var msg MsgMap

		switch result {
		case fprintdEnrollStatusCompleted:
			// 录入指纹成功，保存指纹名
			f, err := newFingerNameConfig(d.user.uuid)
			if err != nil {
				logger.Warning(err)
			} else {
				logger.Infof("stdName %s, fingerName %s", d.curEnrollFinger.stdName, d.curEnrollFinger.fingerName)
				err = f.set(d.curEnrollFinger.stdName, d.curEnrollFinger.fingerName)
				if err != nil {
					logger.Warning(err)
				}
			}
			code = pkgfp.EnrollStatusCompleted

		case fprintdEnrollStatusFailed:
			code = pkgfp.EnrollStatusFailed

		case fprintdEnrollStatusStagePassed:
			code = pkgfp.EnrollStatusStagePassed

		case fprintdEnrollStatusRetryScan:
			code = pkgfp.EnrollStatusRetry

		case fprintdEnrollStatusSwipeTooShort:
			code = pkgfp.EnrollStatusRetry
			msg = MsgMap{
				"subcode": pkgfp.EnrollStatusRetrySubcodeSwipeTooShort,
			}

		case fprintdEnrollStatusFingerNotCentered:
			code = pkgfp.EnrollStatusRetry
			msg = MsgMap{
				"subcode": pkgfp.EnrollStatusRetrySubcodeFingerNotCentered,
			}

		case fprintdEnrollStatusRemoveAndRetry:
			code = pkgfp.EnrollStatusRetry
			msg = MsgMap{
				"subcode": pkgfp.EnrollStatusRetrySubcodeRemoveAndRetry,
			}

		case fprintdEnrollStatusDataFull:
			code = pkgfp.EnrollStatusFailed
			msg = MsgMap{
				"subcode": pkgfp.EnrollStatusFailedSubcodeDataFull,
			}

		case fprintdEnrollStatusEnrollUnknownError:
			code = pkgfp.EnrollStatusFailed
			msg = MsgMap{
				"subcode": pkgfp.EnrollStatusFailedSubcodeUnknownError,
			}

		case fprintdEnrollStatusEnrollDisconnected:
			code = pkgfp.EnrollStatusDisconnected
		default:
			logger.Warning("unknown fprintd enroll status result", result)
			return
		}

		d.emitSignalEnrollStatus(code, msg)
	})
	if err != nil {
		logger.Warning(err)
	}

	_, err = d.core.ConnectVerifyStatus(func(result string, done bool) {
		var code int
		var msg MsgMap

		switch result {
		case fprintdVerifyStatusMatch:
			code = pkgfp.VerifyStatusMatch

		case fprintdVerifyStatusNoMatch:
			code = pkgfp.VerifyStatusNoMatch

		case fprintdVerifyStatusRetryScan:
			code = pkgfp.VerifyStatusRetry

		case fprintdVerifyStatusSwipeTooShort:
			code = pkgfp.VerifyStatusRetry
			msg = MsgMap{
				"subcode": pkgfp.VerifyStatusRetrySubcodeSwipeTooShort,
			}

		case fprintdVerifyStatusFingerNotCentered:
			code = pkgfp.VerifyStatusRetry
			msg = MsgMap{
				"subcode": pkgfp.VerifyStatusRetrySubcodeFingerNotCentered,
			}

		case fprintdVerifyStatusRemoveAndRetry:
			code = pkgfp.VerifyStatusRetry
			msg = MsgMap{
				"subcode": pkgfp.VerifyStatusRetrySubcodeRemoveAndRetry,
			}

		case fprintdVerifyStatusDisconnected:
			code = pkgfp.VerifyStatusDisconnected

		case fprintdVerifyStatusUnknownError:
			code = pkgfp.VerifyStatusError
			msg = MsgMap{
				"subcode": pkgfp.VerifyStatusErrorSubcodeUnknown,
			}
		default:
			logger.Warning("unknown fprintd verify status result", result)
			return
		}
		d.emitSignalVerifyStatus(d.user.name, code, msg)
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (d *FprintdDevice) name() (string, error) {
	return d.core.Name().Get(0)
}

func (d *FprintdDevice) available() (bool, error) {
	return true, nil
}

func (d *FprintdDevice) capability() (int32, error) {
	return 0, nil
}

func (d *FprintdDevice) doClaim(userInfo UserInfo, claimed bool) error {
	var err error
	if claimed {
		err = d.core.Claim(0, userInfo.name)
	} else {
		err = d.core.Release(0)
	}
	return err
}

var standardFinger = strv.Strv{
	"left-thumb",
	"left-index-finger",
	"left-middle-finger",
	"left-ring-finger",
	"left-little-finger",
	"right-thumb",
	"right-index-finger",
	"right-middle-finger",
	"right-ring-finger",
	"right-little-finger",
}

func (d *FprintdDevice) enroll(finger string) error {
	fin, err := d.core.ListEnrolledFingers(0, d.user.name)
	if err != nil && err.Error() != "Failed to discover prints" {
		return err
	}

	logger.Info("read finger name from module is:", fin)
	stdName := ""
	for _, v := range standardFinger {
		if !strv.Strv(fin).Contains(v) {
			stdName = v
			break
		}
	}

	if stdName == "" {
		return errors.New("fingerprint name too many")
	}
	logger.Infof("stdName %s, fingerName %s", stdName, finger)

	f, err := newFingerNameConfig(d.user.uuid)
	if err != nil {
		logger.Warning(err)
		return nil
	}

	if f.isFingerExists(finger) {
		return errors.New("fingerprint exists")
	}

	err = d.core.EnrollStart(0, stdName)
	if err == nil {
		d.curEnrollFinger.fingerName = finger
		d.curEnrollFinger.stdName = stdName
	}
	return err
}

func (d *FprintdDevice) stopEnroll() error {
	err := d.core.EnrollStop(0)
	return err
}

func (d *FprintdDevice) verify(finger string) error {
	err := d.core.VerifyStart(0, finger)
	return err
}

func (d *FprintdDevice) stopVerify() error {
	err := d.core.VerifyStop(0)
	return err
}

func (d *FprintdDevice) deleteFinger(userInfo UserInfo, finger string) error {
	f, err := newFingerNameConfig(userInfo.uuid)
	if err != nil {
		return err
	}

	stdName := f.getStdName(finger)
	err = d.core.DeleteEnrolledFinger(0, stdName)
	if err != nil {
		return err
	}

	err = f.delete(stdName)
	if err != nil {
		logger.Warning(err)
	}

	return nil
}

func (d *FprintdDevice) deleteAllFingers(userInfo UserInfo) error {
	err := d.core.DeleteEnrolledFingers(0, userInfo.name)
	if err != nil {
		return err
	}

	f, err := newFingerNameConfig(userInfo.uuid)
	if err != nil {
		logger.Warning(err)
		return nil
	}

	err = f.clear()
	if err != nil {
		logger.Warning(err)
	}

	return nil
}

func (d *FprintdDevice) listFingers(userInfo UserInfo) ([]string, error) {
	stdNames, err := d.core.ListEnrolledFingers(0, userInfo.name)
	if err != nil {
		return nil, err
	}

	f, err := newFingerNameConfig(userInfo.uuid)
	if err != nil {
		return nil, err
	}

	return f.getFingerNames(stdNames), nil
}

func (d *FprintdDevice) renameFinger(userInfo UserInfo, finger, newName string) error {
	f, err := newFingerNameConfig(userInfo.uuid)
	if err != nil {
		return nil
	}

	return f.rename(finger, newName)
}

func newFingerNameConfig(uuid string) (*FingerNameConfig, error) {
	err := os.MkdirAll(fprintdNameMapConfigDir, 0755)
	if err != nil {
		return nil, err
	}

	f := &FingerNameConfig{}
	f.filename = filepath.Join(fprintdNameMapConfigDir, uuid+".json")

	file, err := os.Open(f.filename)
	if err != nil {
		if os.IsNotExist(err) {
			f.data.StdNames = nil
			f.data.FingerMap = make(map[string]string)
			return f, nil
		}

		return nil, err
	}
	defer func() {
		err = file.Close()
		if err != nil {
			logger.Warning("failed to close file", err)
		}
	}()

	dec := json.NewDecoder(file)
	err = dec.Decode(&f.data)
	if err != nil {
		return nil, err
	}

	if f.data.FingerMap == nil {
		f.data.FingerMap = make(map[string]string)
	}

	logger.Debug("fingerprint map", f.data.FingerMap)
	return f, nil
}

func (f *FingerNameConfig) save() error {
	data, err := json.Marshal(f.data)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(f.filename, data, 0644)
}

func (f *FingerNameConfig) isFingerExists(fingerName string) bool {
	for _, v := range f.data.FingerMap {
		if v == fingerName {
			return true
		}
	}

	return false
}

func (f *FingerNameConfig) getStdName(fingerName string) string {
	for k, v := range f.data.FingerMap {
		if v == fingerName {
			return k
		}
	}

	return ""
}

func (f *FingerNameConfig) setWithoutSave(stdName, fingerName string) {
	_, ok := f.data.FingerMap[stdName]
	if !ok {
		f.data.StdNames = append(f.data.StdNames, stdName)
	}

	f.data.FingerMap[stdName] = fingerName
}

func (f *FingerNameConfig) set(stdName, fingerName string) error {
	f.setWithoutSave(stdName, fingerName)

	return f.save()
}

func (f *FingerNameConfig) delete(stdName string) error {
	i := -1
	for k, v := range f.data.StdNames {
		if v == stdName {
			i = k
			break
		}
	}

	if i == -1 {
		return nil
	}

	copy(f.data.StdNames[i:], f.data.StdNames[i+1:])
	f.data.StdNames[len(f.data.StdNames)-1] = ""
	f.data.StdNames = f.data.StdNames[:len(f.data.StdNames)-1]
	delete(f.data.FingerMap, stdName)

	return f.save()
}

func (f *FingerNameConfig) rename(origName, newName string) error {
	i := ""
	for k, v := range f.data.FingerMap {
		if v == origName {
			i = k
			break
		}
	}

	if i == "" {
		return errors.New("finger name not exists")
	}

	f.data.FingerMap[i] = newName

	return f.save()
}

func (f *FingerNameConfig) getFingerNames(stdNames []string) []string {
	res := make([]string, 0, len(stdNames))
	for _, v := range f.data.StdNames {
		// 如果这个数据没有从接口中获取到，说明这条数据多了（可能直接从 fprintd 的接口删除）
		if !strv.Strv(stdNames).Contains(v) {
			logger.Warningf("fingerprint stdName %s deleted", v)
			continue
		}

		res = append(res, f.data.FingerMap[v])
	}

	// 结果与从接口中获取到的数据匹配，说明 map 没有少数据
	if len(stdNames) == len(res) {
		return res
	}

	// map 有少数据，添加为原名
	for _, v := range stdNames {
		// map 中存在这个指纹，略过
		if strv.Strv(f.data.StdNames).Contains(v) {
			continue
		}

		f.setWithoutSave(v, v)
		res = append(res, v)
	}

	err := f.save()
	if err != nil {
		logger.Warning(err)
	}

	return res
}

func (f *FingerNameConfig) clear() error {
	f.data.StdNames = nil
	f.data.FingerMap = make(map[string]string)

	return f.save()
}
