package fingerprint

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFingerprintFakeDevice_emptyFunction(t *testing.T) {
	// 跑一下空函数
	fakeDev := newFakeDevice(&Manager{})
	fakeDev.select0()
	fakeDev.deselect()
	fakeDev.available()
	fakeDev.capability()
	fakeDev.doClaim(UserInfo{}, true)
	fakeDev.stopEnroll()
	fakeDev.stopVerify()
	fakeDev.deleteFinger(UserInfo{}, "")
	fakeDev.deleteAllFingers(UserInfo{})
	fakeDev.listFingers(UserInfo{})
	fakeDev.renameFinger(UserInfo{}, "", "")
}

func TestFingerprintFakeDevice_getVerifyStatusCodesForEmit(t *testing.T) {
	type test struct {
		name string
		dev  *fakeDevice
		len  int
	}
	tests := []test{
		{name: "getVerifyStatusCodesForEmit find", dev: &fakeDevice{codesIdx: 1, codesSlice: [][]int{{1, 2}, {3, 4, 5}}}, len: 3},
		{name: "getVerifyStatusCodesForEmit not find", dev: &fakeDevice{codesIdx: 2, codesSlice: [][]int{{1, 2}, {3, 4, 5}}}, len: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arr := tt.dev.getVerifyStatusCodesForEmit()
			assert.Equal(t, tt.len, len(arr))
		})
	}
}
