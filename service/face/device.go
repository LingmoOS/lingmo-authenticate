package face

type deviceMethodI interface {
	claim(bool) error
	startEnroll(string, string) error
	stopEnroll() error
	startVerify(string, int) error
	stopVerify() error
	listFaces(string) ([]string, error)
	deleteFace(string, string) error
	renameFace(string, string, string) error
	deleteFaces(string) error
	setDefaultDevice(string) error
	getShareMemInfo() (string, string, int32, error)
}

type devicePropI interface {
	name() (string, error)
	serviceName() string
	claimed() (bool, error)
	capability() (int32, error)
	status() (int32, error)
	supportDevices() ([]string, error)
	defaultDevice() (string, error)
}

type device interface {
	devSelect()
	devDeSelect()
	setInvokeId(string)
	connectStatusChanged(fn func(hasValue bool, status int32)) error
	removeStatusConnect()

	devicePropI
	deviceMethodI
}
