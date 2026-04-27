package fingerprint

import (
	"errors"
	"strings"
	"sync"
	"time"

	"pkg.deepin.io/dde/authentication/pkg/fingerprint"
)

const (
	DeviceStateNormal = 1 << iota
	DeviceStateClaimed
)

const (
	DeviceTimeoutSeconds = 3
)

type baseDevice struct {
	m       *Manager
	mu      sync.Mutex
	sender  string
	user    UserInfo
	claimFn ClaimFn
}

func checkTimeout(ch chan struct{}) bool {
	var err bool = false
	select {
	case <-ch:
		break
	case <-time.After(time.Second * DeviceTimeoutSeconds):
		err = true
		break
	}
	return err
}

type ClaimFn func(userInfo UserInfo, claimed bool) error

func (d *baseDevice) isClaimed() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.sender != ""
}

func (d *baseDevice) checkClaimed(sender string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.sender == "" {
		return errors.New("not claimed")
	}

	if d.sender != sender {
		return errors.New("sender not equal")
	}

	return nil
}

func (d *baseDevice) claim(sender string, userInfo UserInfo, claimed bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	curClaimed := d.sender != ""

	if claimed {
		// claim
		if curClaimed {
			return errors.New("device is already claimed")
		} else {
			var err error
			claimOk := make(chan bool)
			go func() {
				err = d.claimFn(userInfo, true)
				claimOk <- true
			}()

			select {
			case <-claimOk:
				if err != nil {
					// indicate that the device has been claimed
					if strings.Contains(err.Error(), "claimed") {
						err = nil
					}
				}
				break
			case <-time.After(time.Second * DeviceTimeoutSeconds):
				err = errors.New("claim timeout")
				break
			}

			if err != nil {
				return err
			}

			d.sender = sender
			d.user = userInfo
		}
	} else {
		// release
		if curClaimed {
			if d.sender != sender {
				return errors.New("sender not equal")
			}
			d.release()
		} else {
			logger.Info("device is not claimed")
			return errors.New("device is not claimed")
		}
	}

	return nil
}

func (d *baseDevice) handleNameLost(name string) (handled bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sender != name {
		return
	}
	handled = true

	logger.Debugf("name %s lost, auto release", name)
	d.release()
	return
}

func (d *baseDevice) release() {
	var err error
	releaseOk := make(chan bool)

	go func() {
		err = d.claimFn(d.user, false)
		releaseOk <- true
	}()

	select {
	case <-releaseOk:
		if err == errors.New("Device was already claimed") {
			err = nil
		}
		break
	case <-time.After(time.Second * DeviceTimeoutSeconds):
		err = errors.New("release timeout")
	}
	if err != nil {
		// failed to release
		logger.Warning("failed to release:", err)
	}
	d.sender = ""
	d.user = UserInfo{}
}

func (d *baseDevice) emitSignalEnrollStatus(code int, msg MsgMap) {
	d.m.emitSignalEnrollStatus(d.user.name, code, msg)
}

func (d *baseDevice) emitSignalEnrollStatusRaw(code int, msg string) {
	d.m.emitSignalEnrollStatusRaw(d.user.name, code, msg)
}

func (d *baseDevice) emitSignalVerifyStatus(username string, code int, msg MsgMap) {
	d.m.emitSignalVerifyStatus(username, code, msg)
}

func (d *baseDevice) emitSignalVerifyStatusRaw(code int, msg string) {
	d.m.emitSignalVerifyStatusRaw(d.user.name, code, msg)
}

type baseDeviceMethods interface {
	claim(sender string, userInfo UserInfo, claimed bool) error
	isClaimed() bool
	checkClaimed(sender string) error
	handleNameLost(name string) (handled bool)
}

type Device interface {
	baseDeviceMethods

	select0()
	deselect()

	name() (string, error)
	available() (bool, error)
	capability() (int32, error)

	enroll(finger string) error
	stopEnroll() error

	verify(finger string) error
	stopVerify() error

	deleteFinger(userInfo UserInfo, finger string) error
	deleteAllFingers(userInfo UserInfo) error
	listFingers(userInfo UserInfo) ([]string, error)
	renameFinger(userInfo UserInfo, finger string, newName string) error
}

type UserInfo struct {
	name string
	uuid string
}

type DeviceInfo struct {
	fingerprint.DeviceInfo
	from Device
}
