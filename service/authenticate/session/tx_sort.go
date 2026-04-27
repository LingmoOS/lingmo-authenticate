package session

import (
	. "pkg.deepin.io/dde/authentication/service/authcommon"
)

type txSort []Tx

func (txs txSort) Len() int {
	return len(txs)
}

func (txs txSort) Less(i, j int) bool {
	return AuthTypeToPriority(txs[i].getType()) < AuthTypeToPriority(txs[j].getType())
}

func (txs txSort) Swap(i, j int) {
	txs[i], txs[j] = txs[j], txs[i]
}
