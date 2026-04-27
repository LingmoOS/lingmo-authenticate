package authenticate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_loadLimitStates(t *testing.T) {
	timeLayout := "2006-01-02T15:04:05Z"

	tests := []struct {
		name     string
		filename string
		want     map[string][]LimitState
		wantErr  bool
	}{
		{
			name:     "loadLimitStates",
			filename: "testdata/limit-states.json",
			want: map[string][]LimitState{
				"test1": {
					{
						Type:        "password",
						NumFailures: 0,
						LockAt: func() time.Time {
							t, _ := time.Parse(timeLayout, "0001-01-01T00:00:00Z")
							return t
						}(),
					},
					{
						Type:        "active directory",
						NumFailures: 0,
						LockAt: func() time.Time {
							t, _ := time.Parse(timeLayout, "0001-01-01T00:00:00Z")
							return t
						}(),
					},
					{
						Type:        "fingerprint",
						NumFailures: 3,
						LockAt: func() time.Time {
							t, _ := time.Parse(timeLayout, "2020-11-11T09:35:04Z")
							return t
						}(),
					},
					{
						Type:        "face",
						NumFailures: 0,
						LockAt: func() time.Time {
							t, _ := time.Parse(timeLayout, "0001-01-01T00:00:00Z")
							return t
						}(),
					},
				},
				"uos": {
					{
						Type:        "password",
						NumFailures: 0,
						LockAt: func() time.Time {
							t, _ := time.Parse(timeLayout, "0001-01-01T00:00:00Z")
							return t
						}(),
					},
					{
						Type:        "fingerprint",
						NumFailures: 0,
						LockAt: func() time.Time {
							t, _ := time.Parse(timeLayout, "0001-01-01T00:00:00Z")
							return t
						}(),
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var states map[string][]LimitState
			err := loadLimitStates(tt.filename, &states)
			if tt.wantErr {
				assert.NotNil(t, err)
				return
			}

			assert.Nil(t, err)
			assert.Equal(t, tt.want, states)
		})
	}
}
