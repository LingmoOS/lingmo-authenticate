package multifactor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"pkg.deepin.io/dde/authentication/service/authcommon"
)

func Test_toConfigObject(t *testing.T) {
	type args struct {
		b []byte
	}
	tests := []struct {
		name             string
		args             args
		want             *Config
		isDefaultService []bool
		wantErr          bool
		authType         []string
	}{
		{
			name: "toConfigObject_defaultService",
			args: args{
				b: []byte(`{
								"ApplicationType" : "lock",
								"RequestVerificationType": [
									{
										"Type": "password"
									},
									{
										"Type": "ukey"
									}
								]
							}`),
			},
			want: &Config{
				ApplicationType:         "lock",
				RequestVerificationType: []*AuthTypeConfig{{Type: "password"}, {Type: "ukey"}},
			},
			isDefaultService: []bool{true, true},
			wantErr:          false,
			authType:         []string{authcommon.AuthTypePassword, authcommon.AuthTypeUKey},
		},
		{
			name: "toConfigObject_notDefaultService",
			args: args{
				b: []byte(`{
								"ApplicationType" : "lock",
								"RequestVerificationType": [
									{
										"Type": "password",
										"Service": "xxx"
									},
									{
										"Type": "ukey",
										"Service": "xxx"
									}
								]
							}`),
			},
			want: &Config{
				ApplicationType:         "lock",
				RequestVerificationType: []*AuthTypeConfig{{Type: "password", Service: "xxx"}, {Type: "ukey", Service: "xxx"}},
			},
			isDefaultService: []bool{false, false},
			wantErr:          false,
			authType:         []string{authcommon.AuthTypePassword, authcommon.AuthTypeUKey},
		},
		{
			name: "toConfigObject_error",
			args: args{
				// make pot 中 deepin-update-pot 会报错,故修改
				b: []byte(`{
								"ApplicationType" : "lock",
								"RequestVerificationType": [
									{
										"Type": "password",
										"Service": "xxx"
									},
									{
										"Type": "ukey",
										"Service": "xxx"
									},
								]
							}`),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for id, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toConfigObject(tt.args.b)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.isDefaultService[id], got.IsUseDefaultService(tt.authType[id]))
		})
	}
}

func TestConfig_isValidConfig(t *testing.T) {
	tests := []struct {
		name string
		obj  *Config
		want bool
	}{
		{
			name: "Config_isValidConfig1",
			obj: &Config{
				ApplicationType: "lock",
				RequestVerificationType: []*AuthTypeConfig{
					{Type: "password"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.obj.isValidConfig()
			assert.Equal(t, tt.want, got)
		})
	}
}
