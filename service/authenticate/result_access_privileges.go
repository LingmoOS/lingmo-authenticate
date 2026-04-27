package authenticate

import "sync"

type privilegeConfig struct {
	Master string `json:"MasterExecPath"`
	Agent  string `json:"AgentExecPath"`
}

type privilegesManager struct {
	pConfigs map[int]*privilegeConfig
	pId      int
	mux      sync.Mutex
}

// 特权管理,用于管理类似于lightdm -> greeter的应用
func newPrivilegesManager() *privilegesManager {
	return &privilegesManager{pConfigs: make(map[int]*privilegeConfig)}
}

// 查询 master 与 agent 是否配置了特权
func (p *privilegesManager) allow(master, agent string) bool {
	p.mux.Lock()
	defer p.mux.Unlock()

	for _, v := range p.pConfigs {
		logger.Debugf("privileges config is: %#+v", v)
		if v.Master == master && v.Agent == agent {
			return true
		}
	}
	return false
}

func (p *privilegesManager) isMasterRegistered(masterPath string) bool {
	p.mux.Lock()
	defer p.mux.Unlock()

	for _, v := range p.pConfigs {
		if v.Master == masterPath {
			return true
		}
	}
	return false
}

func (p *privilegesManager) register(master, agent string) int {
	p.mux.Lock()
	defer p.mux.Unlock()

	p.pId++
	if p.pId == 0 {
		p.pId++
	}
	p.pConfigs[p.pId] = &privilegeConfig{Master: master, Agent: agent}

	return p.pId
}

func (p *privilegesManager) unregister(id int) {
	p.mux.Lock()
	defer p.mux.Unlock()

	delete(p.pConfigs, id)
}
