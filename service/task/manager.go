package task

import "sync"

type Func func(id string, paras ...interface{}) bool

var _manager *Manager

type funcInfo struct {
	fn       Func
	blockRun bool
}

type Manager struct {
	signalTasks    map[string]map[string]*funcInfo
	signalTasksMux sync.Mutex
}

func init() {
	_manager = newManager()
}

func GetTaskManager() *Manager {
	return _manager
}

func newManager() *Manager {
	return &Manager{signalTasks: make(map[string]map[string]*funcInfo)}
}

func (m *Manager) AddSignalTask(signal string, id string, fn Func, blockRun bool) {
	m.signalTasksMux.Lock()
	defer m.signalTasksMux.Unlock()

	if fn == nil {
		return
	}

	if _, ok := m.signalTasks[signal]; !ok {
		m.signalTasks[signal] = make(map[string]*funcInfo)
	}
	// 允许覆盖
	m.signalTasks[signal][id] = &funcInfo{fn: fn, blockRun: blockRun}
}

func (m *Manager) DelSignalTask(signal string, id string) {
	m.signalTasksMux.Lock()
	defer m.signalTasksMux.Unlock()

	if val, ok := m.signalTasks[signal]; ok {
		delete(val, id)
	}
}

func (m *Manager) DoSignalTask(signal string, paras ...interface{}) {
	m.signalTasksMux.Lock()
	defer m.signalTasksMux.Unlock()

	if funcMap, ok := m.signalTasks[signal]; ok {
		for id, funcInfo := range funcMap {
			if funcInfo.blockRun {
				del := funcInfo.fn(id, paras...)
				if del {
					delete(funcMap, id)
				}
			} else {
				go func(id string, fn Func) {
					del := fn(id, paras...)
					if del {
						delete(funcMap, id)
					}
				}(id, funcInfo.fn)
			}
		}
	}
}
