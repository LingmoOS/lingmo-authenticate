package fingerprint

import (
	"errors"
	"testing"

	"github.com/godbus/dbus"
	"github.com/stretchr/testify/assert"

	auth_fp "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.lingmo.daemon.authenticate.fingerprint"
	huawei_fprint "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/com.huawei.fingerprint"
	fd_fprint "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/net.reactivated.fprint"
	ofdbus "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/org.freedesktop.dbus"
	"pkg.deepin.io/dde/authentication/pkg/fingerprint"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil/proxy"
)

func TestFingerprintManager_initFakeDevice(t *testing.T) {
	type test struct {
		name              string
		FakeDeviceEnabled string
		m                 *Manager
		isHasDevs         bool
	}
	tests := []test{
		{name: "initFakeDevice, not has fake deice", FakeDeviceEnabled: "0", m: &Manager{}, isHasDevs: false},
		{name: "initFakeDevice, has fake deice", FakeDeviceEnabled: "1", m: &Manager{}, isHasDevs: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enableBak := FakeDeviceEnabled
			FakeDeviceEnabled = tt.FakeDeviceEnabled
			defer func() {
				FakeDeviceEnabled = enableBak
			}()
			tt.m.initFakeDevice()
			assert.Equal(t, tt.isHasDevs, (len(tt.m.allDevices) != 0))
		})
	}
}

func TestFingerprintManager_initHuaweiDevice(t *testing.T) {
	type test struct {
		name      string
		m         *Manager
		isHasDevs bool
	}
	tests := []test{
		func() test {
			mDbus := new(ofdbus.MockDBus)
			mDbus.MockInterfaceDbusIfc.On("ListActivatableNames", dbus.Flags(0)).Return([]string{"1111", "com.huawei.dev1"}, nil)
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockObject.On("ServiceName_").Return("com.huawei.dev1")
			mFHuawei.MockInterfaceFingerprint.On("SearchDevice", dbus.Flags(0)).Return(true, nil)

			return test{
				name:      "initHuaweiDevice, has huawei deice",
				m:         &Manager{dbusDaemon: mDbus, huaweiFprint: mFHuawei},
				isHasDevs: true,
			}
		}(),
		func() test {
			mDbus := new(ofdbus.MockDBus)
			mDbus.MockInterfaceDbusIfc.On("ListActivatableNames", dbus.Flags(0)).Return([]string{"31", "com.huawei.sss"}, nil)
			mFHuawei := new(huawei_fprint.MockFingerprint)
			mFHuawei.MockObject.On("ServiceName_").Return("com.huawei.dev1")
			mFHuawei.MockInterfaceFingerprint.On("SearchDevice", dbus.Flags(0)).Return(true, nil)

			return test{
				name:      "initHuaweiDevice, not has huawei deice",
				m:         &Manager{dbusDaemon: mDbus, huaweiFprint: mFHuawei},
				isHasDevs: false,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.m.initHuaweiDevice()
			assert.Equal(t, tt.isHasDevs, (len(tt.m.allDevices) != 0))
		})
	}
}

func TestFingerprintManager_initFprintdDevices(t *testing.T) {
	type test struct {
		name      string
		m         *Manager
		isHasDevs bool
	}
	tests := []test{
		func() test {
			mFdFprint := new(fd_fprint.MockManager)
			mFdFprint.MockInterfaceManager.On("GetDevices", dbus.Flags(0)).Return([]dbus.ObjectPath{}, nil)
			return test{
				name:      "initFprintdDevices, empty",
				m:         &Manager{fprintdManager: mFdFprint},
				isHasDevs: false,
			}
		}(),
		// 存在设备的场景不好测，暂时不测
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.m.initFprintdDevices()
			assert.Equal(t, tt.isHasDevs, (len(tt.m.allDevices) != 0))
		})
	}
}

func TestFingerprintManager_getDeviceInfo(t *testing.T) {
	type test struct {
		name      string
		m         *Manager
		dev       *commonDevice
		isHasDevs bool
		devInfo   DeviceInfo
	}
	tests := []test{
		func() test {
			mNameString := new(proxy.MockPropString)
			mNameString.On("Get", dbus.Flags(0)).Return("", errors.New("name error"))
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Name").Return(mNameString)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:      "getDeviceInfo error",
				m:         &Manager{},
				dev:       dev,
				isHasDevs: false,
			}
		}(),
		func() test {
			mNameString := new(proxy.MockPropString)
			mNameString.On("Get", dbus.Flags(0)).Return("aaa", nil)
			mStateInt := new(proxy.MockPropInt32)
			mStateInt.On("Get", dbus.Flags(0)).Return(int32(1), nil)
			mCapInt := new(proxy.MockPropInt32)
			mCapInt.On("Get", dbus.Flags(0)).Return(int32(7), nil)
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Name").Return(mNameString)
			mDevCore.MockInterfaceCommonDevice.On("State").Return(mStateInt)
			mDevCore.MockInterfaceCommonDevice.On("Capability").Return(mCapInt)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:      "getDeviceInfo succ",
				m:         &Manager{},
				dev:       dev,
				isHasDevs: true,
				devInfo: DeviceInfo{
					DeviceInfo: fingerprint.DeviceInfo{
						Name:       "aaa",
						Available:  true,
						Capability: 7,
					},
				},
			}
		}(),
		func() test {
			mNameString := new(proxy.MockPropString)
			mNameString.On("Get", dbus.Flags(0)).Return("aaa", nil)
			mStateInt := new(proxy.MockPropInt32)
			mStateInt.On("Get", dbus.Flags(0)).Return(int32(1), errors.New("test warning"))
			mCapInt := new(proxy.MockPropInt32)
			mCapInt.On("Get", dbus.Flags(0)).Return(int32(9), errors.New("test warning"))
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Name").Return(mNameString)
			mDevCore.MockInterfaceCommonDevice.On("State").Return(mStateInt)
			mDevCore.MockInterfaceCommonDevice.On("Capability").Return(mCapInt)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:      "getDeviceInfo succ but not available",
				m:         &Manager{},
				dev:       dev,
				isHasDevs: true,
				devInfo: DeviceInfo{
					DeviceInfo: fingerprint.DeviceInfo{
						Name:       "aaa",
						Available:  false,
						Capability: 9,
					},
				},
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retDevInfo, err := getDeviceInfo(tt.dev)
			if tt.isHasDevs {
				assert.Equal(t, tt.devInfo.DeviceInfo.Name, retDevInfo.DeviceInfo.Name)
				assert.Equal(t, tt.devInfo.DeviceInfo.Available, retDevInfo.DeviceInfo.Available)
				assert.Equal(t, tt.devInfo.DeviceInfo.Capability, retDevInfo.DeviceInfo.Capability)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintManager_SetDefaultDevice(t *testing.T) {
	type test struct {
		name    string
		devName string
		m       *Manager
		isSucc  bool
	}

	tests := []test{
		func() test {
			devInfos := []DeviceInfo{
				DeviceInfo{
					DeviceInfo: fingerprint.DeviceInfo{
						Name:       "aaa",
						Available:  true,
						Capability: 7,
					},
				},
			}
			return test{
				name:    "SetDefaultDevice not exist",
				devName: "bbb",
				m:       &Manager{deviceInfoList: devInfos},
				isSucc:  false,
			}
		}(),
		func() test {
			devInfos := []DeviceInfo{
				DeviceInfo{
					DeviceInfo: fingerprint.DeviceInfo{
						Name:       "aaa",
						Available:  false,
						Capability: 7,
					},
				},
			}
			return test{
				name:    "SetDefaultDevice not available",
				devName: "aaa",
				m:       &Manager{deviceInfoList: devInfos},
				isSucc:  false,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbusErr := tt.m.SetDefaultDevice(tt.devName)
			assert.Equal(t, tt.isSucc, (dbusErr.Error() == ""))
		})
	}
}

func TestFingerprintManager_toString(t *testing.T) {
	type test struct {
		name    string
		msg     MsgMap
		isEmpty bool
	}

	tests := []test{
		{name: "toString, empty", msg: MsgMap{}, isEmpty: true},
		{name: "toString, has fake deice", msg: MsgMap{
			"a": "aa",
			"b": 123,
		}, isEmpty: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, _ := tt.msg.toString()
			assert.Equal(t, tt.isEmpty, (ret == ""))
		})
	}
}

func TestFingerprintManager_StopEnroll(t *testing.T) {
	type test struct {
		name   string
		sender string
		m      *Manager
		isSucc bool
	}
	tests := []test{
		func() test {
			return test{
				name:   "StopEnroll error",
				sender: "",
				m:      &Manager{defaultDevice: nil}, // 1 not defaultDevice
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopEnroll", dbus.Flags(0)).Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopEnroll error",
				sender: "", // 2 not sender
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopEnroll", dbus.Flags(0)).Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopEnroll error",
				sender: "bbb", // 3 sender not equal
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopEnroll", dbus.Flags(0)).Return(errors.New("error")) // 4 StopEnroll error

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopEnroll error",
				sender: "sss",
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopEnroll", dbus.Flags(0)).Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopEnroll success",
				sender: "sss",
				m:      &Manager{defaultDevice: dev},
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbusErr := tt.m.StopEnroll(dbus.Sender(tt.sender))
			assert.Equal(t, tt.isSucc, (dbusErr == nil))
		})
	}
}

func TestFingerprintManager_Verify(t *testing.T) {
	type test struct {
		name   string
		sender string
		finger string
		m      *Manager
		isSucc bool
	}
	tests := []test{
		func() test {
			return test{
				name:   "Verify error",
				sender: "",
				finger: "",
				m:      &Manager{defaultDevice: nil}, // 1 not defaultDevice
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Verify", dbus.Flags(0), "111").Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "Verify error",
				sender: "", // 2 not sender
				finger: "111",
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Verify", dbus.Flags(0), "111").Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "Verify error",
				sender: "bbb", // 3 sender not equal
				finger: "111",
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Verify", dbus.Flags(0), "111").Return(errors.New("error")) // 4 Verify error

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "Verify error",
				sender: "sss",
				finger: "111",
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Verify", dbus.Flags(0), "111").Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "Verify success",
				sender: "sss",
				finger: "111",
				m:      &Manager{defaultDevice: dev},
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbusErr := tt.m.Verify(dbus.Sender(tt.sender), tt.finger)
			assert.Equal(t, tt.isSucc, (dbusErr == nil))
		})
	}
}

func TestFingerprintManager_StopVerify(t *testing.T) {
	type test struct {
		name   string
		sender string
		m      *Manager
		isSucc bool
	}
	tests := []test{
		func() test {
			return test{
				name:   "StopVerify error",
				sender: "",
				m:      &Manager{defaultDevice: nil}, // 1 not defaultDevice
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopVerify", dbus.Flags(0)).Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopVerify error",
				sender: "", // 2 not sender
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopVerify", dbus.Flags(0)).Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopVerify error",
				sender: "bbb", // 3 sender not equal
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopVerify", dbus.Flags(0)).Return(errors.New("error")) // 4 StopVerify error

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopVerify error",
				sender: "sss",
				m:      &Manager{defaultDevice: dev},
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("StopVerify", dbus.Flags(0)).Return(nil)

			dev := &commonDevice{core: mDevCore}
			dev.baseDevice.sender = "sss"
			return test{
				name:   "StopVerify success",
				sender: "sss",
				m:      &Manager{defaultDevice: dev},
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbusErr := tt.m.StopVerify(dbus.Sender(tt.sender))
			assert.Equal(t, tt.isSucc, (dbusErr == nil))
		})
	}
}
