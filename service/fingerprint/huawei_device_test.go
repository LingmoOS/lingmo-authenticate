package fingerprint

import (
	"errors"
	"testing"

	"github.com/godbus/dbus"
	"github.com/stretchr/testify/assert"

	huawei_fprint "github.com/linuxdeepin/go-dbus-factory/com.huawei.fingerprint"
	pkgfp "pkg.deepin.io/dde/authentication/pkg/fingerprint"
)

func TestFingerprintHuawei_newHuaweiDevice(t *testing.T) {
	mFHuawei := new(huawei_fprint.MockFingerprint)
	m := &Manager{huaweiFprint: mFHuawei}
	hd := newHuaweiDevice(m)
	assert.NotNil(t, hd)
}

func TestFingerprintHuawei_doClaim(t *testing.T) {
	type test struct {
		name    string
		dev     *huaweiDevice
		claimed bool
		isSucc  bool
	}
	tests := []test{
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusIdle), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:    "doClaim succ",
				dev:     dev,
				claimed: true,
				isSucc:  true,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusIdle), errors.New("error"))
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:    "doClaim failed",
				dev:     dev,
				claimed: true,
				isSucc:  false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), errors.New("error"))
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:    "doClaim failed",
				dev:     dev,
				claimed: true,
				isSucc:  false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(-1), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:    "doClaim failed",
				dev:     dev,
				claimed: true,
				isSucc:  false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:    "doClaim succ",
				dev:     dev,
				claimed: true,
				isSucc:  true,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:    "doClaim succ",
				dev:     dev,
				claimed: false,
				isSucc:  true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.doClaim(UserInfo{}, tt.claimed)
			if tt.isSucc {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintHuawei_name(t *testing.T) {
	type test struct {
		name    string
		dev     *huaweiDevice
		devName string
	}
	tests := []test{
		{name: "name succ", dev: &huaweiDevice{}, devName: "huawei"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devName, err := tt.dev.name()
			assert.NoError(t, err)
			assert.Equal(t, devName, tt.devName)
		})
	}
}

func TestFingerprintHuawei_available(t *testing.T) {
	type test struct {
		name        string
		dev         *huaweiDevice
		isAvailable bool
	}
	tests := []test{
		{name: "available succ", dev: &huaweiDevice{}, isAvailable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAvailable, err := tt.dev.available()
			assert.NoError(t, err)
			assert.Equal(t, isAvailable, tt.isAvailable)
		})
	}
}

func TestFingerprintHuawei_capability(t *testing.T) {
	type test struct {
		name       string
		dev        *huaweiDevice
		capability int32
	}
	tests := []test{
		{name: "capability succ", dev: &huaweiDevice{}, capability: pkgfp.CapabilityOneKeyLogin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			capability, err := tt.dev.capability()
			assert.NoError(t, err)
			assert.Equal(t, capability, tt.capability)
		})
	}
}

func TestFingerprintHuawei_deselect(t *testing.T) {
	type test struct {
		name   string
		dev    *huaweiDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockObject.On("RemoveAllHandlers").Return()
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "deselect succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.dev.deselect()
		})
	}
}

func TestFingerprintHuawei_stop(t *testing.T) {
	type test struct {
		name   string
		dev    *huaweiDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusIdle), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stop succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusIdle), errors.New("error"))
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stop failed",
				dev:    dev,
				isSucc: false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), errors.New("error"))
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stop failed",
				dev:    dev,
				isSucc: false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(-1), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stop failed",
				dev:    dev,
				isSucc: false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusBusy), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stop succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.stop()
			if tt.isSucc {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintHuawei_stopEnroll(t *testing.T) {
	type test struct {
		name   string
		dev    *huaweiDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusIdle), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stopEnroll succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.stopEnroll()
			if tt.isSucc {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintHuawei_verify(t *testing.T) {
	type test struct {
		name   string
		dev    *huaweiDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("IdentifyWithMultipleUser", dbus.FlagNoReplyExpected).Return(nil)
			dev := &huaweiDevice{core: mFHuawei, baseDevice: baseDevice{user: UserInfo{name: pkgfp.EmptyUsername, uuid: ""}}}
			return test{
				name:   "verify succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("IdentifyWithMultipleUser", dbus.FlagNoReplyExpected).Return(errors.New("error"))
			dev := &huaweiDevice{core: mFHuawei, baseDevice: baseDevice{user: UserInfo{name: pkgfp.EmptyUsername, uuid: ""}}}
			return test{
				name:   "verify failed",
				dev:    dev,
				isSucc: false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("ClearPovImage", dbus.Flags(0)).Return(int32(0), errors.New("error"))
			dev := &huaweiDevice{core: mFHuawei, baseDevice: baseDevice{user: UserInfo{name: "123", uuid: ""}}}
			return test{
				name:   "verify failed",
				dev:    dev,
				isSucc: false,
			}
		}(),
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("ClearPovImage", dbus.Flags(0)).Return(int32(0), nil)
			mFHuawei.MockInterfaceFingerprint.On("Identify", dbus.FlagNoReplyExpected, "abc").Return(nil)
			dev := &huaweiDevice{core: mFHuawei, baseDevice: baseDevice{user: UserInfo{name: "123", uuid: "abc"}}}
			return test{
				name:   "verify succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.verify("")
			if tt.isSucc {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintHuawei_stopVerify(t *testing.T) {
	type test struct {
		name   string
		dev    *huaweiDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockInterfaceFingerprint.On("GetStatus", dbus.Flags(0)).Return(int32(huaweiDeviceStatusIdle), nil)
			mFHuawei.MockInterfaceFingerprint.On("Close", dbus.Flags(0)).Return(int32(0), nil)
			dev := &huaweiDevice{core: mFHuawei}
			return test{
				name:   "stopVerify succ",
				dev:    dev,
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.stopVerify()
			if tt.isSucc {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintHuawei_codeFingerName(t *testing.T) {
	type test struct {
		name string
		code string
	}
	tests := []test{
		{name: "", code: "123"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := encodeFingerName(tt.code)
			codeNew := decodeFingerName(data)
			assert.Equal(t, tt.code, codeNew)
		})
	}
}
