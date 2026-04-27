package session

import (
	"fmt"
	"sort"
	"sync"
)

type Controller interface {
	init(string, string, []Tx, signalProxy)
	authenticate(int, int) int
	checkTx(username string, appType int, refFlag int32) int32
	listenResultCh()
	genPrompt([]Tx) string
	genAuthFactors() []authFactor
	end(statusCode, int)
	isEnded() bool
	deviceStatusProxy
}

type baseController struct {
	pathId   string
	txs      []Tx
	proxy    signalProxy
	ended    bool
	endedMu  sync.Mutex
	username string
}

func (bc *baseController) markEnded() {
	bc.endedMu.Lock()
	bc.ended = true
	bc.endedMu.Unlock()
}

func (bc *baseController) isEnded() bool {
	bc.endedMu.Lock()
	defer bc.endedMu.Unlock()
	return bc.ended
}

func (bc *baseController) init(id string, username string, txs []Tx, proxy signalProxy) {
	bc.proxy = proxy
	bc.username = username
	bc.txs = txs
	bc.pathId = id
	sort.Sort(txSort(bc.txs))

}

func (bc *baseController) String() string {
	return fmt.Sprintf("< session id = %s >", bc.pathId)
}

func (bc *baseController) getCurrentSessionPath() string {
	return bc.pathId
}

type signalProxy interface {
	emitStatus(int, statusCode, string)
	updateLimits(statusCode, int)
}
