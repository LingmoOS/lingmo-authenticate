package fingerprint

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/godbus/dbus"
	huawei_fprint "github.com/linuxdeepin/go-dbus-factory/com.huawei.fingerprint"
	pkgfp "pkg.deepin.io/dde/authentication/pkg/fingerprint"
)

type huaweiDevice struct {
	baseDevice
	core huawei_fprint.Fingerprint
}

const (
	encodePrefix = "b64:"
)

func newHuaweiDevice(m *Manager) *huaweiDevice {
	d := &huaweiDevice{
		core: m.huaweiFprint,
	}
	d.m = m
	d.claimFn = d.doClaim
	return d
}

func (d *huaweiDevice) doClaim(_ UserInfo, claimed bool) error {
	if claimed {
		// claim
		status, err := d.core.GetStatus(0)
		if err != nil {
			return err
		}

		if status == huaweiDeviceStatusBusy {
			logger.Warning("device is busy, call close first")
			err = d.doClose()
			if err != nil {
				return err
			}
		}

	} else {
		// release
		// TODO
		return nil
	}
	return nil
}

func (d *huaweiDevice) name() (string, error) {
	return "huawei", nil
}

func (d *huaweiDevice) available() (bool, error) {
	return true, nil
}

func (d *huaweiDevice) capability() (int32, error) {
	return pkgfp.CapabilityOneKeyLogin, nil
}

// nolint
const (
	huaweiDeviceStatusBusy = 1
	huaweiDeviceStatusIdle = 0
)

func (d *huaweiDevice) select0() {
	logger.Debug("huaweiDevice.select")
	d.listenSignal()
}

func (d *huaweiDevice) deselect() {
	logger.Debug("huaweiDevice.deselect")
	d.core.RemoveAllHandlers()
}

func (d *huaweiDevice) listenSignal() {
	d.core.InitSignalExt(d.m.sysSigLoop, true)
	_, err := d.core.ConnectEnrollStatus(func(progress int32, result int32) {
		logger.Debug("EnrollStatus", progress, result)
		if d.user.uuid == "" {
			return
		}
		d.handleSignalEnrollStatus(progress, result)
	})
	if err != nil {
		logger.Warning(err)
	}

	_, err = d.core.ConnectIdentifyStatus(func(result int32) {
		if d.user.uuid == "" {
			return
		}
		d.handleSignalIdentifyStatus(d.user.name, result)
	})
	if err != nil {
		logger.Warning(err)
	}

	_, err = d.core.ConnectIdentifyNoAccount(func(result int32, uuid string) {
		username := d.user.name
		if uuid != "" {
			userInfo, err := d.m.findUserByUUID(uuid)
			if err != nil {
				logger.Warning(err)
				return
			}

			username = userInfo.name
		}
		d.handleSignalIdentifyStatus(username, result)
	})
	if err != nil {
		logger.Warning(err)
	}
}

func (d *huaweiDevice) handleSignalEnrollStatus(progress int32, result int32) {
	logger.Debug("signal EnrollStatus", progress, result)
	var code int
	var msg MsgMap

	switch result {
	case -2:
		// 没进行设备初始化就进行录入操作
		code = pkgfp.EnrollStatusFailed
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusFailedSubcodeUnknownError,
		}
		logger.Debug("failed, no device initialization")
	case -1:
		// 指纹录入错误（指纹录入错误，结束指纹录入，多为函数的参数问题引发的错误）
		code = pkgfp.EnrollStatusFailed
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusFailedSubcodeUnknownError,
		}
		logger.Debug("failed")
	case 1:
		if progress == 100 {
			// 指纹录入完成（指纹录入以及指纹模板保存完成，结束指纹录入）
			code = pkgfp.EnrollStatusCompleted
			logger.Debug("completed")
		} else {
			logger.Warningf("ignore invalid signal EnrollStatus(%d,%d)", progress, result)
		}
	case 2:
		// 指纹录入失败（指纹录入失败，结束指纹录入，多为指纹设备异常出现的错误）
		code = pkgfp.EnrollStatusFailed
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusFailedSubcodeUnknownError,
		}
		logger.Debug("failed")
	case 3:
		// 单张指纹图像采图完成
		code = pkgfp.EnrollStatusStagePassed
		msg = MsgMap{
			"progress": int(progress),
		}
		logger.Debug("Single fingerprint image acquisition completed")

	case 4:
		// 当前手指指纹模板已存在，需换其他手指录入指纹
		code = pkgfp.EnrollStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusRetrySubcodeExist,
		}
		logger.Debug("The current finger fingerprint template already exists. You need to change the fingerprint of other fingers.")

	case 104:
		code = pkgfp.EnrollStatusRetry
		logger.Warning("unknown enroll result", result)

	case 100, 105:
		// 指纹图像质量太差，或其他设备扫描的原因需要重新录入指纹
		code = pkgfp.EnrollStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusRetrySubcodeQualityBad,
		}
		logger.Debug("The fingerprint image quality is too bad, or the reason for other device scanning needs to re-enter the fingerprint")

	case 106:
		// 生成的指纹模板已重复（指纹采图结束后自动生成的指纹模板与存在的指纹模板重复，结束指纹录入）
		code = pkgfp.EnrollStatusFailed
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusFailedSubcodeTemplateDuplicated,
		}
		logger.Debug("The generated fingerprint template has been duplicated")

	case 107:
		// 指纹向左移动
		code = pkgfp.EnrollStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusRetrySubcodeRepetitionRateHigh,
		}
		logger.Debug("move left")
	case 108:
		// 指纹向下移动
		code = pkgfp.EnrollStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusRetrySubcodeRepetitionRateHigh,
		}
		logger.Debug("move down")
	case 109:
		// 指纹向右移动
		code = pkgfp.EnrollStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusRetrySubcodeRepetitionRateHigh,
		}
		logger.Debug("move right")
	case 110:
		// 指纹向上移动
		code = pkgfp.EnrollStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.EnrollStatusRetrySubcodeRepetitionRateHigh,
		}
		logger.Debug("move up")

	default:
		logger.Warning("unknown EnrollStatus result", result)
		return
	}

	d.emitSignalEnrollStatus(code, msg)
}

func (d *huaweiDevice) handleSignalIdentifyStatus(username string, result int32) {
	logger.Debug("signal IdentifyStatus", result)
	var code int
	var msg MsgMap

	switch result {
	case -2:
		// 设备初始化失败
		code = pkgfp.VerifyStatusError
		msg = MsgMap{
			"subcode": pkgfp.VerifyStatusErrorSubcodeUnavailable,
		}

	case -1:
		// 认证超时，以后会被废弃
		code = pkgfp.VerifyStatusError
		msg = MsgMap{
			"subcode": pkgfp.VerifyStatusErrorSubcodeUnknown,
		}

	case 0:
		// 认证成功
		code = pkgfp.VerifyStatusMatch

	case 1:
		// 认证失败
		code = pkgfp.VerifyStatusNoMatch

	case 100:
		// 图像不可用
		code = pkgfp.VerifyStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.VerifyStatusRetrySubcodeQualityBad,
		}

	case 101:
		// 按压时间过短
		code = pkgfp.VerifyStatusRetry
		msg = MsgMap{
			"subcode": pkgfp.VerifyStatusRetrySubcodeTouchTimeShort,
		}

	case 110:
		// 指纹设备重启，需要重新发起验证
		logger.Debug("fingerprint device need to restart")
		err := d.close()
		if err != nil {
			logger.Warning("failed to close device:", err)
			return
		}
		err = d.core.Identify(dbus.FlagNoReplyExpected, d.user.uuid)
		if err != nil {
			logger.Warning("failed to restart verify:", err)
		}
		return

	default:
		logger.Warning("unknown IdentifyStatus result", result)
		return
	}

	d.emitSignalVerifyStatus(username, code, msg)

	// 华为设备重试状态会关闭认证，这里重新发起认证请求
	// 一键登录时不重新发起认证
	if code == pkgfp.VerifyStatusRetry && d.user.uuid != pkgfp.EmptyUUID {
		err := d.verify("")
		if err != nil {
			logger.Warning("failed to restart verify", err)

			// 重新发起认证失败，发送错误通知
			code = pkgfp.VerifyStatusError
			msg = MsgMap{
				"subcode": pkgfp.VerifyStatusErrorSubcodeUnknown,
			}
			d.emitSignalVerifyStatus(username, code, msg)
		}
	}
}

func (d *huaweiDevice) doClose() error {
	closeRet, err := d.core.Close(0)
	if err != nil {
		return err
	}

	if closeRet == -1 {
		return errors.New("failed to close")
	}
	return nil
}

func (d *huaweiDevice) enroll(finger string) error {
	dir, err := ensureHuaweiFprintDir(d.user.uuid)
	if err != nil {
		return err
	}

	fingerFilename := encodeFingerName(finger)
	filename := filepath.Join(dir, fingerFilename)
	_, err = os.Stat(filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		} // else file not exist, pass
	} else {
		// file exist
		err = os.Remove(filename)
		if err != nil && !os.IsNotExist(err) {
			return err
		}

		reloadRet, err := d.core.Reload(0, HuaweiDeleteTypeOne)
		if err != nil {
			return err
		}
		if reloadRet == -1 {
			return errors.New("failed to load")
		}
	}

	err = d.core.Enroll(dbus.FlagNoReplyExpected, filename, d.user.uuid)
	return err
}

const (
	HuaweiFprintDir = "/var/lib/dde-daemon/fingerprint/huawei"

	HuaweiDeleteTypeOne = 0
	HuaweiDeleteTypeAll = 1
)

func ensureHuaweiFprintDir(userUuid string) (dir string, err error) {
	err = os.MkdirAll(HuaweiFprintDir, 0755)
	if err != nil {
		return
	}
	dir = filepath.Join(HuaweiFprintDir, userUuid)
	err = os.Mkdir(dir, 0700)
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	return dir, nil
}

func (d *huaweiDevice) stop() error {
	return d.close()
}

func (d *huaweiDevice) close() error {
	status, err := d.core.GetStatus(0)
	if err != nil {
		return err
	}

	if status == huaweiDeviceStatusBusy {
		return d.doClose()
	} // else status is idle, no need call close
	return nil
}

func (d *huaweiDevice) stopEnroll() error {
	return d.stop()
}

func (d *huaweiDevice) verify(_ string) error {
	var err error
	if d.user.name == pkgfp.EmptyUsername {
		err = d.core.IdentifyWithMultipleUser(dbus.FlagNoReplyExpected)
	} else {
		// 清图，一键唤醒时的账户若是没有指纹，指纹会一直保存，
		// 所以在发起认证前需要清图避免直接使用了认证前的保存的指纹
		_, err = d.core.ClearPovImage(0)
		if err != nil {
			return err
		}

		err = d.core.Identify(dbus.FlagNoReplyExpected, d.user.uuid)
	}
	return err
}

func (d *huaweiDevice) stopVerify() error {
	return d.stop()
}

func (d *huaweiDevice) deleteFinger(userInfo UserInfo, finger string) error {
	dir, err := ensureHuaweiFprintDir(userInfo.uuid)
	if err != nil {
		return err
	}

	fingerFilename := encodeFingerName(finger)
	err = os.Remove(filepath.Join(dir, fingerFilename))
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Remove(filepath.Join(dir, finger))
			if os.IsNotExist(err) {
				return errors.New("not found finger")
			}
		}
		return err
	}

	reloadRet, err := d.core.Reload(0, HuaweiDeleteTypeOne)
	if err != nil {
		return err
	}
	if reloadRet == -1 {
		return errors.New("failed to reload")
	}
	return nil
}

func (d *huaweiDevice) deleteAllFingers(userInfo UserInfo) error {
	dir := filepath.Join(HuaweiFprintDir, userInfo.uuid)

	err := os.RemoveAll(dir)
	if err != nil {
		return err
	}

	reloadRet, err := d.core.Reload(0, HuaweiDeleteTypeAll)
	if err != nil {
		return err
	}
	if reloadRet == -1 {
		return errors.New("failed to reload")
	}
	return nil
}

func (d *huaweiDevice) listFingers(userInfo UserInfo) ([]string, error) {
	dir, err := ensureHuaweiFprintDir(userInfo.uuid)
	if err != nil {
		return nil, err
	}

	fileInfoList, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	sort.Slice(fileInfoList, func(i, j int) bool {
		return fileInfoList[i].ModTime().Before(fileInfoList[j].ModTime())
	})

	var result []string
	for _, fileInfo := range fileInfoList {
		if fileInfo.IsDir() {
			continue
		}

		fingerName := decodeFingerName(fileInfo.Name())
		result = append(result, fingerName)
	}

	return result, nil
}

func (d *huaweiDevice) renameFinger(userInfo UserInfo, finger string, newName string) error {
	dir, err := ensureHuaweiFprintDir(userInfo.uuid)
	if err != nil {
		return err
	}

	oldFilename := encodeFingerName(finger)
	newFilename := encodeFingerName(newName)

	oldPath := filepath.Join(dir, oldFilename)
	newPath := filepath.Join(dir, newFilename)

	_, err = os.Stat(newPath)
	if err == nil {
		return fmt.Errorf("finger %s exists", newName)
	}

	err = os.Rename(oldPath, newPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = os.Rename(filepath.Join(dir, finger), newPath)
			if os.IsNotExist(err) {
				return errors.New("not found finger")
			}
		}
		return err
	}

	reloadRet, err := d.core.Reload(0, HuaweiDeleteTypeOne)
	if err != nil {
		return err
	}
	if reloadRet == -1 {
		return errors.New("failed to reload")
	}
	return nil
}

func encodeFingerName(finger string) string {
	return encodePrefix + base64.RawURLEncoding.EncodeToString([]byte(finger))
}

func decodeFingerName(finger string) string {
	if strings.HasPrefix(finger, encodePrefix) {
		finger = strings.TrimPrefix(finger, encodePrefix)
		res, err := base64.RawURLEncoding.DecodeString(finger)
		if err == nil {
			return string(res)
		}

		logger.Warning("failed to decode finger name", finger, err)
	}

	return finger
}
