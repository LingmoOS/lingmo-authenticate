package authcommon

import (
	"errors"
	"time"
)

type Func func(...interface{}) error

var ErrSyncCallTimeout = errors.New("timeout")

func SyncCallWithTimeout(timeout time.Duration, fn Func, fnParas ...interface{}) error {
	if fn == nil {
		return errors.New("invalid para")
	}
	callOk := make(chan bool)
	var err error
	go func() {
		err = fn(fnParas...)
		callOk <- true
	}()

	select {
	case <-callOk:
		return err

	case <-time.After(timeout):
		return ErrSyncCallTimeout
	}
}
