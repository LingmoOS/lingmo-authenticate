package fingerprint

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFingerprintDevice_isClaimed(t *testing.T) {
	type test struct {
		name      string
		dev       *baseDevice
		isClaimed bool
	}
	tests := []test{
		{name: "isClaimed true", dev: &baseDevice{sender: "123"}, isClaimed: true},
		{name: "isClaimed false", dev: &baseDevice{sender: ""}, isClaimed: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isClaimed := tt.dev.isClaimed()
			assert.Equal(t, tt.isClaimed, isClaimed)
		})
	}
}

func TestFingerprintDevice_claim(t *testing.T) {
	type test struct {
		name     string
		dev      *baseDevice
		sender   string
		userInfo UserInfo
		claimed  bool
		isSucc   bool
	}
	tests := []test{
		{
			name:     "claim false",
			dev:      &baseDevice{sender: "", claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return nil })},
			sender:   "", // error empty
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  false,
			isSucc:   false,
		},
		{
			name:     "claim false",
			dev:      &baseDevice{sender: "123", claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return nil })},
			sender:   "456", // error "123" != "456"
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  false,
			isSucc:   false,
		},
		{
			name: "claim true",
			dev: &baseDevice{
				sender:  "123",
				user:    UserInfo{},
				claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return errors.New("not error, test warning") }),
			},
			sender:   "123",
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  false,
			isSucc:   true,
		},
		{
			name:     "claim false",
			dev:      &baseDevice{sender: "123", claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return nil })},
			sender:   "123",
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  true, // error
			isSucc:   false,
		},
		{
			name: "claim true",
			dev: &baseDevice{
				sender:  "",
				user:    UserInfo{},
				claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return nil }),
			},
			sender:   "",
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  true,
			isSucc:   true,
		},
		{
			name: "claim false",
			dev: &baseDevice{
				sender:  "",
				user:    UserInfo{},
				claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return errors.New("error") }),
			},
			sender:   "",
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  true,
			isSucc:   false,
		},
		{
			name: "claim true",
			dev: &baseDevice{
				sender:  "",
				user:    UserInfo{},
				claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return errors.New("claimed") }),
			},
			sender:   "",
			userInfo: UserInfo{uuid: "", name: ""},
			claimed:  true,
			isSucc:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.dev.claim(tt.sender, tt.userInfo, tt.claimed)
			if tt.isSucc {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestFingerprintDevice_handleNameLost(t *testing.T) {
	type test struct {
		name    string
		dev     *baseDevice
		dName   string
		handled bool
	}
	tests := []test{
		{
			name:    "handleNameLost false",
			dev:     &baseDevice{sender: "123", claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return nil })},
			dName:   "456", // error, sender != name
			handled: false,
		},
		{
			name:    "handleNameLost true",
			dev:     &baseDevice{sender: "123", claimFn: ClaimFn(func(userInfo UserInfo, claimed bool) error { return nil })},
			dName:   "123",
			handled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handled := tt.dev.handleNameLost(tt.dName)
			assert.Equal(t, tt.handled, handled)
		})
	}
}
