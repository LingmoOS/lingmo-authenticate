package fingerprint

import (
	"errors"
	"io/ioutil"
	"os"
	"testing"

	"github.com/godbus/dbus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	auth_fd_fp "github.com/LingmoOS/golang-github-lingmo-go-dbus-factory/net.reactivated.fprint"
	"github.com/LingmoOS/golang-github-lingmo-go-lib/dbusutil/proxy"
)

func TestFingerprintFprintdDevice_deselect(t *testing.T) {
	type test struct {
		name   string
		dev    *FprintdDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockObject.On("RemoveAllHandlers").Return()
			dev := &FprintdDevice{core: mDevCore}
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

func TestFingerprintFprintdDevice_name(t *testing.T) {
	type test struct {
		name    string
		dev     *FprintdDevice
		retName string
	}
	tests := []test{
		func() test {
			mNameString := new(proxy.MockPropString)
			mNameString.On("Get", dbus.Flags(0)).Return("aaa", nil)
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("Name").Return(mNameString)
			dev := &FprintdDevice{core: mDevCore}
			return test{
				name:    "name succ",
				dev:     dev,
				retName: "aaa",
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			name, err := tt.dev.name()
			assert.NoError(t, err)
			assert.Equal(t, name, tt.retName)
		})
	}
}

func TestFingerprintFprintdDevice_available(t *testing.T) {
	type test struct {
		name        string
		dev         *FprintdDevice
		isAvailable bool
	}
	tests := []test{
		{name: "available succ", dev: &FprintdDevice{}, isAvailable: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isAvailable, err := tt.dev.available()
			assert.NoError(t, err)
			assert.Equal(t, isAvailable, tt.isAvailable)
		})
	}
}

func TestFingerprintFprintdDevice_capability(t *testing.T) {
	type test struct {
		name string
		dev  *FprintdDevice
		cap  int32
	}
	tests := []test{
		{name: "capability succ", dev: &FprintdDevice{}, cap: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cap, err := tt.dev.capability()
			assert.NoError(t, err)
			assert.Equal(t, cap, tt.cap)
		})
	}
}

func TestFingerprintFprintdDevice_doClaim(t *testing.T) {
	type test struct {
		name      string
		dev       *FprintdDevice
		userInfo  UserInfo
		isClaimed bool
		isSucc    bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("Claim", dbus.Flags(0), "n123").Return(nil)
			mDevCore.MockInterfaceDevice.On("Release", dbus.Flags(0)).Return(nil)
			dev := &FprintdDevice{core: mDevCore}
			return test{
				name:      "doClaim Claim",
				dev:       dev,
				userInfo:  UserInfo{uuid: "", name: "n123"},
				isClaimed: true,
				isSucc:    true,
			}
		}(),
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("Claim", dbus.Flags(0), "n123").Return(nil)
			mDevCore.MockInterfaceDevice.On("Release", dbus.Flags(0)).Return(nil)
			dev := &FprintdDevice{core: mDevCore}
			return test{
				name:      "doClaim Release",
				dev:       dev,
				userInfo:  UserInfo{uuid: "", name: "n123"},
				isClaimed: false,
				isSucc:    true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.doClaim(tt.userInfo, tt.isClaimed)
			if tt.isSucc {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFingerprintFprintdDevice_enroll(t *testing.T) {
	type test struct {
		name   string
		dev    *FprintdDevice
		finger string
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("ListEnrolledFingers", dbus.Flags(0), "n123").Return([]string{}, errors.New("error"))
			dev := &FprintdDevice{core: mDevCore, baseDevice: baseDevice{user: UserInfo{uuid: "", name: "n123"}}}
			return test{
				name:   "enroll failed",
				dev:    dev,
				finger: "f123",
				isSucc: false,
			}
		}(),
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("ListEnrolledFingers", dbus.Flags(0), "n123").Return([]string(standardFinger), nil)
			dev := &FprintdDevice{core: mDevCore, baseDevice: baseDevice{user: UserInfo{uuid: "", name: "n123"}}}
			return test{
				name:   "enroll failed",
				dev:    dev,
				finger: "f123",
				isSucc: false,
			}
		}(),
		// 成功场景需要root权限，暂不测
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.enroll(tt.finger)
			if !tt.isSucc {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintFprintdDevice_stopEnroll(t *testing.T) {
	type test struct {
		name   string
		dev    *FprintdDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("EnrollStop", dbus.Flags(0)).Return(nil)
			dev := &FprintdDevice{core: mDevCore}
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
			}
		})
	}
}

func TestFingerprintFprintdDevice_verify(t *testing.T) {
	type test struct {
		name   string
		dev    *FprintdDevice
		finger string
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("VerifyStart", dbus.Flags(0), "f123").Return(nil)
			dev := &FprintdDevice{core: mDevCore}
			return test{
				name:   "verify succ",
				dev:    dev,
				finger: "f123",
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.verify(tt.finger)
			if tt.isSucc {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFingerprintFprintdDevice_stopVerify(t *testing.T) {
	type test struct {
		name   string
		dev    *FprintdDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fd_fp.MockDevice)
			mDevCore.MockInterfaceDevice.On("VerifyStop", dbus.Flags(0)).Return(nil)
			dev := &FprintdDevice{core: mDevCore}
			return test{
				name:   "VerifyStop succ",
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
			}
		})
	}
}

func TestFingerNameConfig_isFingerExists(t *testing.T) {
	type test struct {
		name       string
		cfg        *FingerNameConfig
		fingerName string
		isFind     bool
	}
	cfg := &FingerNameConfig{
		data: struct {
			StdNames  []string
			FingerMap map[string]string
		}{
			StdNames:  nil,
			FingerMap: map[string]string{"ss": "111", "ss2": "222"},
		},
	}

	tests := []test{
		{
			name:       "isFingerExists true",
			cfg:        cfg,
			fingerName: "111",
			isFind:     true,
		},
		{
			name:       "isFingerExists false",
			cfg:        cfg,
			fingerName: "a1",
			isFind:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isFind := tt.cfg.isFingerExists(tt.fingerName)
			assert.Equal(t, isFind, tt.isFind)
		})
	}
}

func TestFingerNameConfig_getStdName(t *testing.T) {
	type test struct {
		name       string
		cfg        *FingerNameConfig
		fingerName string
		stdName    string
		isSucc     bool
	}
	cfg := &FingerNameConfig{
		data: struct {
			StdNames  []string
			FingerMap map[string]string
		}{
			StdNames:  nil,
			FingerMap: map[string]string{"ss": "111", "ss2": "222"},
		},
	}

	tests := []test{
		{
			name:       "getStdName false",
			cfg:        cfg,
			fingerName: "111",
			stdName:    "123",
			isSucc:     false,
		},
		{
			name:       "getStdName true",
			cfg:        cfg,
			fingerName: "111",
			stdName:    "ss",
			isSucc:     true,
		},
		{
			name:       "getStdName false",
			cfg:        cfg,
			fingerName: "a1",
			stdName:    "ss",
			isSucc:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdName := tt.cfg.getStdName(tt.fingerName)
			assert.Equal(t, tt.isSucc, (stdName == tt.stdName))
		})
	}
}

func TestFingerNameConfig_FingerMap(t *testing.T) {
	type test struct {
		name          string
		cfg           *FingerNameConfig
		fingerName    string
		fingerNameNew string
		stdName       string
	}

	testDataPath := "./TemporaryTestDataDirectoryNeedDelete"
	err := os.Mkdir(testDataPath, 0777)
	require.Nil(t, err)
	defer func() {
		err := os.RemoveAll(testDataPath)
		require.Nil(t, err)
	}()
	tmpfile, err := ioutil.TempFile(testDataPath, "test.json")
	require.Nil(t, err)
	defer tmpfile.Close()

	tests := []test{
		{
			name: "FingerMap true",
			cfg: &FingerNameConfig{
				filename: "./TemporaryTestDataDirectoryNeedDelete/test.json",
				data: struct {
					StdNames  []string
					FingerMap map[string]string
				}{
					StdNames:  []string{"ss", "ss2"},
					FingerMap: map[string]string{"ss": "111", "ss2": "222"},
				},
			},
			fingerName:    "333",
			stdName:       "ss3",
			fingerNameNew: "3333",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.set(tt.stdName, tt.fingerName)
			require.NoError(t, err)
			err = tt.cfg.rename(tt.fingerName, tt.fingerNameNew)
			require.NoError(t, err)
			err = tt.cfg.delete(tt.stdName)
			require.NoError(t, err)
			err = tt.cfg.clear()
			require.NoError(t, err)
		})
	}
}

func TestFingerNameConfig_getFingerNames(t *testing.T) {
	type test struct {
		name        string
		cfg         *FingerNameConfig
		stdNameList []string
	}

	testDataPath := "./TemporaryTestDataDirectoryNeedDelete"
	err := os.Mkdir(testDataPath, 0777)
	require.Nil(t, err)
	defer func() {
		err := os.RemoveAll(testDataPath)
		require.Nil(t, err)
	}()
	tmpfile, err := ioutil.TempFile(testDataPath, "test.json")
	require.Nil(t, err)
	defer tmpfile.Close()

	tests := []test{
		{
			name: "getFingerNames true",
			cfg: &FingerNameConfig{
				filename: "./TemporaryTestDataDirectoryNeedDelete/test.json",
				data: struct {
					StdNames  []string
					FingerMap map[string]string
				}{
					StdNames:  []string{"ss", "ss2", "ss3"},
					FingerMap: map[string]string{},
				},
			},
			stdNameList: []string{"ss", "ss2", "ss3"},
		},
		{
			name: "getFingerNames true",
			cfg: &FingerNameConfig{
				filename: "./TemporaryTestDataDirectoryNeedDelete/test.json",
				data: struct {
					StdNames  []string
					FingerMap map[string]string
				}{
					StdNames:  []string{"ss", "ss2", "ss3"},
					FingerMap: map[string]string{},
				},
			},
			stdNameList: []string{"ss", "ss2"},
		},
		{
			name: "getFingerNames true",
			cfg: &FingerNameConfig{
				filename: "./TemporaryTestDataDirectoryNeedDelete/test.json",
				data: struct {
					StdNames  []string
					FingerMap map[string]string
				}{
					StdNames:  []string{"ss", "ss2"},
					FingerMap: map[string]string{},
				},
			},
			stdNameList: []string{"ss", "ss2", "ss3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names := tt.cfg.getFingerNames(tt.stdNameList)
			assert.Equal(t, len(tt.stdNameList), len(names))
		})
	}
}
