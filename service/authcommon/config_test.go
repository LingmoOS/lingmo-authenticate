package authcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetInterfaceConfigs(t *testing.T) {
	type args struct {
		interfacesDir string
		type0         int
	}
	tests := []struct {
		name    string
		args    args
		want    []*InterfaceConfigWithFileName
		wantErr bool
	}{
		{
			name: "getInterfaceConfigs",
			args: args{
				interfacesDir: "testdata/interfaces",
				type0:         InterfaceTypeFingerprint,
			},
			want: []*InterfaceConfigWithFileName{
				{
					InterfaceConfig: &InterfaceConfig{
						Service:     "com.pixelauth.fingerService",
						Path:        "/com/pixelauth/fingerService",
						Interface:   "com.pixelauth.fingerService",
						Type:        InterfaceTypeFingerprint,
						StorageType: 1,
					},
					FileName: "testdata/interfaces/pixelauthFinger.conf",
				},
			},
			wantErr: false,
		},
		{
			name: "getInterfaceConfigs_notExist",
			args: args{
				interfacesDir: "testdata/not_exist",
				type0:         InterfaceTypeFingerprint,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetInterfaceConfigs(tt.args.interfacesDir, tt.args.type0)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLoadInterfaceConfig(t *testing.T) {
	type args struct {
		filename string
		type0    int
	}
	tests := []struct {
		name    string
		args    args
		want    *InterfaceConfig
		wantErr bool
	}{
		{
			name: "getInterfaceConfigs",
			args: args{
				filename: "testdata/interfaces/pixelauthFinger.conf",
				type0:    InterfaceTypeFingerprint,
			},
			want: &InterfaceConfig{
				Service:     "com.pixelauth.fingerService",
				Path:        "/com/pixelauth/fingerService",
				Interface:   "com.pixelauth.fingerService",
				Type:        1,
				StorageType: 1,
			},
			wantErr: false,
		},
		{
			name: "getInterfaceConfigs_notExist",
			args: args{
				filename: "testdata/interfaces/not_exist",
				type0:    InterfaceTypeFingerprint,
			},
			wantErr: true,
		},
		{
			name: "getInterfaceConfigs_notValid",
			args: args{
				filename: "testdata/interfaces/pixelauthFinger_notValid.conf",
				type0:    InterfaceTypeFingerprint,
			},
			wantErr: true,
		},
		{
			name: "getInterfaceConfigs_wrongType",
			args: args{
				filename: "testdata/interfaces/pixelauthFinger.conf",
				type0:    InterfaceTypeFace,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := LoadInterfaceConfig(tt.args.filename, tt.args.type0)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
