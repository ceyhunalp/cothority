package main

import (
	"bufio"
	"go.dedis.ch/onet/v3/log"
	"os"
	"strconv"
)

const MAX_TXN_CNT = 7

func ReadFile(txnFile string, blkFile string) ([]int, []int, error) {
	f, err := os.Open(txnFile)
	if err != nil {
		return nil, nil, err
	}
	var txns []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txn, err := strconv.Atoi(scanner.Text())
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		txns = append(txns, txn)
	}
	f.Close()

	f, err = os.Open(blkFile)
	if err != nil {
		return nil, nil, err
	}
	var blks []int
	scanner = bufio.NewScanner(f)
	for scanner.Scan() {
		blk, err := strconv.Atoi(scanner.Text())
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
		blks = append(blks, blk)
	}
	f.Close()
	return txns, blks, err
}
