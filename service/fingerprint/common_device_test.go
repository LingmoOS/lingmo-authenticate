package fingerprint

import (
	"testing"

	"github.com/godbus/dbus"
	"github.com/stretchr/testify/assert"

	auth_fp "github.com/linuxdeepin/go-dbus-factory/com.deepin.daemon.authenticate.fingerprint"
)

func TestFingerprintCommonDevice_deselect(t *testing.T) {
	type test struct {
		name   string
		dev    *commonDevice
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockObject.On("RemoveAllHandlers").Return()
			dev := &commonDevice{core: mDevCore}
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

func TestFingerprintCommonDevice_doClaim(t *testing.T) {
	type test struct {
		name      string
		dev       *commonDevice
		userInfo  UserInfo
		isClaimed bool
		isSucc    bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Claim", dbus.Flags(0), "123", true).Return(nil)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:      "doClaim succ",
				dev:       dev,
				userInfo:  UserInfo{uuid: "123", name: ""},
				isClaimed: true,
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

func TestFingerprintCommonDevice_enroll(t *testing.T) {
	type test struct {
		name   string
		dev    *commonDevice
		finger string
		isSucc bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("Enroll", dbus.Flags(0), "u123", "f123").Return(nil)
			dev := &commonDevice{core: mDevCore, baseDevice: baseDevice{user: UserInfo{uuid: "u123", name: ""}}}
			return test{
				name:   "enroll succ",
				dev:    dev,
				finger: "f123",
				isSucc: true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.enroll(tt.finger)
			if tt.isSucc {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFingerprintCommonDevice_deleteFinger(t *testing.T) {
	type test struct {
		name     string
		dev      *commonDevice
		userInfo UserInfo
		finger   string
		isSucc   bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("DeleteFinger", dbus.Flags(0), "uuid123", "finger123").Return(nil)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:     "deleteFinger succ",
				dev:      dev,
				userInfo: UserInfo{uuid: "uuid123", name: ""},
				finger:   "finger123",
				isSucc:   true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.deleteFinger(tt.userInfo, tt.finger)
			if tt.isSucc {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFingerprintCommonDevice_deleteAllFingers(t *testing.T) {
	type test struct {
		name     string
		dev      *commonDevice
		userInfo UserInfo
		isSucc   bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("DeleteAllFingers", dbus.Flags(0), "uuid123").Return(nil)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:     "deleteAllFingers succ",
				dev:      dev,
				userInfo: UserInfo{uuid: "uuid123", name: ""},
				isSucc:   true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.deleteAllFingers(tt.userInfo)
			if tt.isSucc {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFingerprintCommonDevice_listFingers(t *testing.T) {
	type test struct {
		name     string
		dev      *commonDevice
		userInfo UserInfo
		isSucc   bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("ListFingers", dbus.Flags(0), "uuid123").Return([]string{"f1", "f8"}, nil)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:     "listFingers succ",
				dev:      dev,
				userInfo: UserInfo{uuid: "uuid123", name: ""},
				isSucc:   true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flist, err := tt.dev.listFingers(tt.userInfo)
			if tt.isSucc {
				assert.NoError(t, err)
				assert.Len(t, flist, 2)
			}
		})
	}
}

func TestFingerprintCommonDevice_renameFinger(t *testing.T) {
	type test struct {
		name     string
		dev      *commonDevice
		userInfo UserInfo
		finger   string
		newName  string
		isSucc   bool
	}
	tests := []test{
		func() test {
			mDevCore := new(auth_fp.MockCommonDevice)
			mDevCore.MockInterfaceCommonDevice.On("RenameFinger", dbus.Flags(0), "uuid123", "finger123", "new123").Return(nil)
			dev := &commonDevice{core: mDevCore}
			return test{
				name:     "renameFinger succ",
				dev:      dev,
				userInfo: UserInfo{uuid: "uuid123", name: ""},
				finger:   "finger123",
				newName:  "new123",
				isSucc:   true,
			}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.renameFinger(tt.userInfo, tt.finger, tt.newName)
			if tt.isSucc {
				assert.NoError(t, err)
			}
		})
	}
}
