package ukey

type uKeyCapability int32

const (
	capabilitySingle uKeyCapability = iota
	capabilityMulti
)

type uKeyType int32

const (
	typeNormal uKeyType = iota
	typeDongle
)

type Device interface {
	handleNameLost(name string) (handled bool)
	setServiceName(name string)
	getServiceName() string
	setVerifyId(string)

	devSelect()
	devDeselect()

	name() (string, error)
	state() (int32, error)
	type0() (int32, error)
	isClaimed() bool
	capability() (int32, error)

	verify(username, id string) error
	stopVerify(username, id string) error
	setPin(username, id string, pin string) error
	setSessionPath(username, id string, path string) error
	getPINLength(username string) (int32, error)
	getUserList() ([]string, error)
}

type baseDevice struct {
	m           *Manager
	serviceName string
	id          string
}

func (d *baseDevice) emitSignalVerifyStatus(id string, msg string) {
	d.m.emitSignalVerifyResult(id, msg)
}

func (d *baseDevice) setVerifyId(id string) {
	d.id = id
}
