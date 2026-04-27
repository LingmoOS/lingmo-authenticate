package fingerprint

import (
	"time"

	pkgfp "pkg.deepin.io/dde/authentication/pkg/fingerprint"
)

type fakeDevice struct {
	baseDevice
	codesSlice [][]int
	codesIdx   int
}

func (d *fakeDevice) select0() {
	logger.Debug("fakeDevice.select")
}

func (d *fakeDevice) deselect() {
	logger.Debug("fakeDevice.deselect")
}

func (d *fakeDevice) name() (string, error) {
	return "fake", nil
}

func (d *fakeDevice) available() (bool, error) {
	return true, nil
}

func (d *fakeDevice) capability() (int32, error) {
	return 0, nil
}

func newFakeDevice(m *Manager) *fakeDevice {
	d := &fakeDevice{
		codesSlice: [][]int{
			{pkgfp.VerifyStatusNoMatch},
			{pkgfp.VerifyStatusRetry, pkgfp.VerifyStatusRetry, pkgfp.VerifyStatusNoMatch},
			{pkgfp.VerifyStatusError},
		},
	}
	d.m = m
	d.claimFn = d.doClaim
	return d
}

func (d *fakeDevice) doClaim(userInfo UserInfo, claimed bool) error {
	logger.Debug("fakeDevice.claim", userInfo, claimed)
	return nil
}

func (d *fakeDevice) enroll(finger string) error {
	logger.Debug("fakeDevice.enroll", finger)
	go func() {
		time.Sleep(time.Second)
		d.emitSignalEnrollStatus(pkgfp.EnrollStatusStagePassed, nil)
		time.Sleep(time.Second)
		d.emitSignalEnrollStatus(pkgfp.EnrollStatusStagePassed, nil)
		time.Sleep(time.Second)
		d.emitSignalEnrollStatus(pkgfp.EnrollStatusStagePassed, nil)
		time.Sleep(time.Second)
		d.emitSignalEnrollStatus(pkgfp.EnrollStatusCompleted, nil)
	}()
	return nil
}

func (d *fakeDevice) stopEnroll() error {
	logger.Debug("fakeDevice.stopEnroll")
	return nil
}

func (d *fakeDevice) verify(finger string) error {
	logger.Debug("fakeDevice.verify", d.user.name, finger)
	go func() {
		codes := d.getVerifyStatusCodesForEmit()
		for _, code := range codes {
			time.Sleep(1 * time.Second)
			d.emitSignalVerifyStatus(d.user.name, code, nil)
		}
	}()
	return nil
}

func (d *fakeDevice) getVerifyStatusCodesForEmit() []int {
	if d.codesIdx < len(d.codesSlice) {
		codes := d.codesSlice[d.codesIdx]
		d.codesIdx++
		return codes
	}
	return []int{pkgfp.VerifyStatusMatch}
}

func (d *fakeDevice) stopVerify() error {
	logger.Debug("fakeDevice.stopVerify")
	return nil
}

func (d *fakeDevice) deleteFinger(userInfo UserInfo, finger string) error {
	logger.Debug("fakeDevice.deleteFinger", userInfo, finger)
	return nil
}

func (d *fakeDevice) deleteAllFingers(userInfo UserInfo) error {
	logger.Debug("fakeDevice.deleteAllFingers", userInfo)
	return nil
}

func (d *fakeDevice) listFingers(userInfo UserInfo) ([]string, error) {
	logger.Debug("fakeDevice.listFingers", userInfo)
	return []string{"left-thumb"}, nil
}

func (d *fakeDevice) renameFinger(userInfo UserInfo, finger, newName string) error {
	logger.Debug("fakeDevice.renameFinger", userInfo, finger, newName)
	return nil
}
