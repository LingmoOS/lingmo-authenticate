package multifactor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pkg.deepin.io/dde/authentication/service/authcommon"
)

func Test_multiFactorConfig_loadConfigs(t *testing.T) {
	type args struct {
		dir string
	}
	tests := []struct {
		name    string
		obj     *MFAConfig
		args    args
		configs []*configWithPriority
	}{
		{
			name: "multiFactorConfig_loadConfigs",
			obj:  newMultiFactor(),
			args: args{
				dir: "testdata/multifactor",
			},
			configs: []*configWithPriority{
				{
					Config: &Config{ApplicationType: "lock",
						RequestVerificationType: []*AuthTypeConfig{{Type: "password"}, {Type: "ukey"}}},
					priority: 1},
				{
					Config: &Config{ApplicationType: "login",
						RequestVerificationType: []*AuthTypeConfig{{Type: "password"}}},
					priority: 1},
			},
		},
		{
			name: "multiFactorConfig_loadConfigs_notExist",
			obj:  newMultiFactor(),
			args: args{
				dir: "testdata/multifactor1",
			},
			configs: nil,
		},
		{
			name: "multiFactorConfig_loadConfigs_notValid",
			obj:  newMultiFactor(),
			args: args{
				dir: "testdata/multifactor_not_valid",
			},
			configs: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.obj.loadConfigs(tt.args.dir)
			assert.Equal(t, len(tt.configs), len(tt.obj.configs))
		})
	}
}

func Test_multiFactorConfig_GetConfig(t *testing.T) {
	type args struct {
		appType int
	}
	type testCase struct {
		name string
		obj  *MFAConfig
		args args
		want *Config
	}
	tests := []testCase{
		func() testCase {
			appType := authcommon.AppTypeLock
			c := &configWithPriority{
				Config: &Config{ApplicationType: "lock"},
			}
			tmp := make(map[string]*configWithPriority)
			tmp["lock"] = c
			return testCase{
				name: "multiFactorConfig_GetConfig",
				obj: &MFAConfig{
					configs: tmp,
				},
				args: args{
					appType: appType,
				},
				want: c.Config,
			}
		}()}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.obj.GetConfig(tt.args.appType)
			assert.Equal(t, tt.want, got)

			want := true
			if tt.want == nil {
				want = false
			}
			got1 := tt.obj.IsProgramConfigured(tt.args.appType)
			assert.Equal(t, want, got1)
		})
	}
}
