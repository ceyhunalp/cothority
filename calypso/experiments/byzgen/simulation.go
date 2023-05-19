package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso/experiments/commons"
	"go.dedis.ch/cothority/v3/calypso/experiments/semicentral"
	"go.dedis.ch/cothority/v3/calypso/ots"
	"go.dedis.ch/cothority/v3/calypso/pqots"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/simul/monitor"
	"golang.org/x/xerrors"
	"math/rand"
	"sync"
	"time"
)

type SimulationService struct {
	onet.SimulationBFTree
	NodeCount       int
	F               int
	Threshold       int
	VerifyThreshold int
	BlockTime       int
	ProtoName       string

	TxnFile      string
	Txns         []int
	NumTxns      int
	NumWriteTxns int
	NumReadTxns  int
	BlkFile      string
	Blks         []int
	NumBlks      int

	Publics  []kyber.Point
	serverPk kyber.Point
}

func init() {
	onet.SimulationRegister("ByzgenSim", ByzgenSim)
}

func ByzgenSim(config string) (onet.Simulation, error) {
	ss := &SimulationService{}
	_, err := toml.Decode(config, ss)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (s *SimulationService) Setup(dir string,
	hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.GetID())
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

func (s *SimulationService) prepareOTSWrites(wDarc *darc.Darc) ([]*ots.Write, [][]*pvss.PubVerShare, [][]byte, error) {
	writes := make([]*ots.Write, MAX_TXN_CNT)
	shares := make([][]*pvss.PubVerShare, MAX_TXN_CNT)
	encData := make([][]byte, MAX_TXN_CNT)
	for i := 0; i < MAX_TXN_CNT; i++ {
		sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
			s.NodeCount, s.Threshold, s.Publics, wDarc.GetID())
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}
		data := make([]byte, 32)
		rand.Read(data)
		ctxt, ctxtHash, err := ots.Encrypt(cothority.Suite, secret, data)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, err
		}
		writes[i] = &ots.Write{
			PolicyID: wDarc.GetID(),
			Shares:   sh,
			Proofs:   pr,
			Publics:  s.Publics,
			CtxtHash: ctxtHash,
		}
		encData[i] = ctxt
		shares[i] = sh
	}
	return writes, shares, encData, nil
}

func (s *SimulationService) runOTS(config *onet.SimulationConfig) error {
	wait := 0
	wrProofs := make([]*byzcoin.Proof, MAX_TXN_CNT)
	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs,
			wDarc := commons.CreateMultiClientDarc(s.ProtoName, MAX_TXN_CNT)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		baseCl := ots.NewClient(byzd.Cl)

		_, err = baseCl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc,
			*wDarc, commons.TXN_WAIT)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++

		writes, shares, encData, err := s.prepareOTSWrites(wDarc)
		if err != nil {
			return err
		}

		var wg sync.WaitGroup
		wg.Add(MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			go func(idx int) {
				defer wg.Done()
				wrReply, err := baseCl.AddWrite(writes[idx], writers[idx],
					wCtrs[idx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++
				wrProofs[idx], err = baseCl.WaitProof(wrReply.InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
			}(i)
		}
		wg.Wait()

		ccs := make([]*ots.Client, MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			ccs[i] = ots.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
		}

		txnIdx := 0
		wIdx := -1
		rIdx := -1
		for blkIdx := 0; blkIdx < s.NumBlks; blkIdx++ {
			numTxns := s.Blks[blkIdx]
			txns := s.Txns[txnIdx : txnIdx+numTxns]
			txnIdx += numTxns
			wg.Add(numTxns)
			for i := 0; i < numTxns; i++ {
				if txns[i] == 1 {
					// Write
					wIdx++
					go func(clIdx int, idx int) {
						defer wg.Done()
						wm := monitor.NewTimeMeasure(fmt.Sprintf("wr_%d", idx))
						// Prepare write
						sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
							s.NodeCount, s.Threshold, s.Publics, wDarc.GetID())
						if err != nil {
							log.Error(err)
						}
						data := make([]byte, 32)
						rand.Read(data)
						_, ctxtHash, err := ots.Encrypt(cothority.Suite, secret, data)
						if err != nil {
							log.Error(err)
						}
						write := &ots.Write{
							PolicyID: wDarc.GetID(),
							Shares:   sh,
							Proofs:   pr,
							Publics:  s.Publics,
							CtxtHash: ctxtHash,
						}
						// Add write
						reply, err := ccs[clIdx].AddWrite(write,
							writers[clIdx], wCtrs[clIdx], *wDarc, wait)
						if err != nil {
							log.Error(err)
						}
						wCtrs[clIdx]++
						wp, err := ccs[clIdx].WaitProof(reply.
							InstanceID, time.Duration(commons.WP_INTERVAL), nil)
						if err != nil {
							log.Error(err)
						}
						if !wp.InclusionProof.Match(reply.InstanceID.Slice()) {
							log.Errorf("write inclusion proof does not match")
						}
						wm.Record()
					}(i, wIdx)
				} else {
					// Read
					rIdx++
					go func(clIdx int, idx int) {
						defer wg.Done()
						rm := monitor.NewTimeMeasure(fmt.Sprintf("r_%d", idx))
						modIdx := idx % MAX_TXN_CNT
						rReply, err := ccs[clIdx].AddRead(wrProofs[modIdx],
							readers[modIdx], rCtrs[modIdx], wait)
						if err != nil {
							log.Error(err)
						}
						rCtrs[modIdx]++
						rProof, err := ccs[clIdx].WaitProof(rReply.
							InstanceID, time.Duration(commons.WP_INTERVAL), nil)
						if err != nil {
							log.Error(err)
						}
						if !rProof.InclusionProof.Match(rReply.InstanceID.Slice()) {
							log.Errorf("read inclusion proof does not match")
						}
						dkr, err := ccs[clIdx].DecryptKey(&ots.OTSDKRequest{
							Roster:    config.Roster,
							Threshold: s.Threshold,
							Read:      *rProof,
							Write:     *wrProofs[modIdx],
						})
						if err != nil {
							log.Error(err)
						}
						var keys []kyber.Point
						var encShares []*pvss.PubVerShare
						g := cothority.Suite.Point().Base()
						decShares := ots.ElGamalDecrypt(cothority.Suite,
							readers[modIdx].Ed25519.Secret, dkr.Reencryptions)
						for _, ds := range decShares {
							keys = append(keys, s.Publics[ds.S.I])
							encShares = append(encShares, shares[modIdx][ds.S.I])
						}
						recSecret, err := pvss.RecoverSecret(cothority.Suite,
							g, keys, encShares, decShares, s.Threshold,
							s.NodeCount)
						if err != nil {
							log.Error(err)
						}
						_, err = ots.Decrypt(recSecret, encData[modIdx])
						if err != nil {
							log.Error(err)
						}
						rm.Record()
					}(i, rIdx)
				}
			}
			wg.Wait()
		}
	}
	return nil
}

func (s *SimulationService) preparePQOTSWrites() ([]*pqots.Write,
	[][]*share.PriShare, [][][]byte, [][]byte, error) {
	encData := make([][]byte, MAX_TXN_CNT)
	writes := make([]*pqots.Write, MAX_TXN_CNT)
	shares := make([][]*share.PriShare, MAX_TXN_CNT)
	rands := make([][][]byte, MAX_TXN_CNT)
	for i := 0; i < MAX_TXN_CNT; i++ {
		var commitments [][]byte
		var err error
		poly := pqots.GenerateSSPoly(s.Threshold)
		shares[i], rands[i], commitments, err = pqots.GenerateCommitments(poly,
			s.NodeCount)
		if err != nil {
			log.Error(err)
			return nil, nil, nil, nil, err
		}
		ticket := make([]byte, 32)
		rand.Read(ticket)
		ctxt, ctxtHash, err := pqots.Encrypt(poly.Secret(), ticket)
		writes[i] = &pqots.Write{Commitments: commitments,
			Publics:  s.Publics,
			CtxtHash: ctxtHash}
		encData[i] = ctxt
	}
	return writes, shares, rands, encData, nil
}

func (s *SimulationService) runPQOTS(config *onet.SimulationConfig) error {
	wait := 0
	wrProofs := make([]*byzcoin.Proof, MAX_TXN_CNT)
	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs,
			wDarc := commons.CreateMultiClientDarc(s.ProtoName, MAX_TXN_CNT)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		baseCl := pqots.NewClient(byzd.Cl)

		_, err = baseCl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc,
			*wDarc, commons.TXN_WAIT)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++

		writes, shares, rands, encData, err := s.preparePQOTSWrites()
		if err != nil {
			return err
		}

		var wg sync.WaitGroup
		wg.Add(MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			go func(idx int) {
				defer wg.Done()
				reply, err := baseCl.VerifyWriteAll(s.VerifyThreshold,
					config.Roster, writes[idx], shares[idx], rands[idx])
				if err != nil {
					log.Error(err)
				}
				wrReply, err := baseCl.AddWrite(writes[idx],
					reply.Sigs, s.VerifyThreshold, writers[idx],
					wCtrs[idx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++
				wrProofs[idx], err = baseCl.WaitProof(wrReply.InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
			}(i)
		}
		wg.Wait()

		ccs := make([]*pqots.Client, MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			ccs[i] = pqots.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
		}

		txnIdx := 0
		wIdx := -1
		rIdx := -1
		for blkIdx := 0; blkIdx < s.NumBlks; blkIdx++ {
			numTxns := s.Blks[blkIdx]
			txns := s.Txns[txnIdx : txnIdx+numTxns]
			txnIdx += numTxns
			wg.Add(numTxns)
			for i := 0; i < numTxns; i++ {
				if txns[i] == 1 {
					// Write
					wIdx++
					go func(clIdx int, idx int) {
						defer wg.Done()
						wm := monitor.NewTimeMeasure(fmt.Sprintf("wr_%d", idx))
						// Prepare write
						var commitments [][]byte
						poly := pqots.GenerateSSPoly(s.Threshold)
						shs, rs, commitments, err := pqots.GenerateCommitments(poly, s.NodeCount)
						if err != nil {
							log.Error(err)
						}
						ticket := make([]byte, 32)
						rand.Read(ticket)
						_, ctxtHash, err := pqots.Encrypt(poly.Secret(), ticket)
						write := &pqots.Write{Commitments: commitments,
							Publics:  s.Publics,
							CtxtHash: ctxtHash}
						// Add write
						reply, err := ccs[clIdx].VerifyWriteAll(s.VerifyThreshold, config.Roster,
							write, shs, rs)
						if err != nil {
							log.Error(err)
						}
						wrReply, err := ccs[clIdx].AddWrite(write,
							reply.Sigs, s.VerifyThreshold, writers[clIdx],
							wCtrs[clIdx], *wDarc, wait)
						if err != nil {
							log.Error(err)
						}
						wCtrs[clIdx]++
						wp, err := ccs[clIdx].WaitProof(wrReply.InstanceID,
							time.Duration(commons.WP_INTERVAL), nil)
						if err != nil {
							log.Error(err)
						}
						if !wp.InclusionProof.Match(wrReply.InstanceID.Slice()) {
							log.Errorf("write inclusion proof does not match")
						}
						wm.Record()
					}(i, wIdx)
				} else {
					// Read
					rIdx++
					go func(clIdx int, idx int) {
						defer wg.Done()
						rm := monitor.NewTimeMeasure(fmt.Sprintf("r_%d", idx))
						modIdx := idx % MAX_TXN_CNT
						rReply, err := ccs[clIdx].AddRead(wrProofs[modIdx],
							readers[modIdx], rCtrs[modIdx], wait)
						if err != nil {
							log.Error(err)
						}
						rCtrs[modIdx]++

						rProof, err := ccs[clIdx].WaitProof(rReply.InstanceID,
							time.Duration(commons.WP_INTERVAL), nil)
						if err != nil {
							log.Error(err)
						}
						if !rProof.InclusionProof.Match(rReply.InstanceID.Slice()) {
							log.Errorf("read inclusion proof does not match")
						}
						dkr, err := ccs[clIdx].DecryptKey(&pqots.PQOTSDKRequest{
							Roster:    config.Roster,
							Threshold: s.Threshold,
							Read:      *rProof,
							Write:     *wrProofs[modIdx],
						})
						if err != nil {
							log.Error(err)
						}
						decShares := pqots.ElGamalDecrypt(cothority.Suite,
							readers[modIdx].Ed25519.Secret, dkr.Reencryptions)
						recSecret, err := share.RecoverSecret(cothority.Suite, decShares,
							s.Threshold, s.NodeCount)
						if err != nil {
							log.Error(err)
						}
						_, err = pqots.Decrypt(recSecret, encData[modIdx])
						if err != nil {
							log.Error(err)
						}
						rm.Record()
					}(i, rIdx)
				}
			}
			wg.Wait()
		}
	}
	return nil
}

func (s *SimulationService) prepareSCWrites(readers []darc.Signer) ([]*semicentral.SCWrite, [][]byte, error) {
	var err error
	encData := make([][]byte, MAX_TXN_CNT)
	writes := make([]*semicentral.SCWrite, MAX_TXN_CNT)
	for i := 0; i < MAX_TXN_CNT; i++ {
		data := make([]byte, 32)
		rand.Read(data)
		writes[i], encData[i], err = semicentral.NewSCWrite(data,
			readers[i].Ed25519.Point, s.serverPk)
		if err != nil {
			log.Error(err)
			return nil, nil, err
		}
	}
	return writes, encData, nil
}

func (s *SimulationService) runSC(config *onet.SimulationConfig) error {
	wait := 0
	storedKeys := make([]string, MAX_TXN_CNT)
	wrProofs := make([]*byzcoin.Proof, MAX_TXN_CNT)

	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs,
			wDarc := commons.CreateMultiClientDarc(s.ProtoName, MAX_TXN_CNT)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		baseCl := semicentral.NewClient(byzd.Cl)

		_, err = baseCl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarc, commons.TXN_WAIT)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++

		writes, encData, err := s.prepareSCWrites(readers)
		if err != nil {
			return err
		}

		var wg sync.WaitGroup
		wg.Add(MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			go func(idx int) {
				defer wg.Done()
				reply, err := baseCl.StoreData(encData[idx],
					writes[idx].DataHash)
				if err != nil {
					log.Error(err)
				}
				storedKeys[idx] = reply.StoredKey
				wReply, err := baseCl.AddWrite(writes[idx], writers[idx],
					wCtrs[idx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++
				wrProofs[idx], err = baseCl.WaitProof(wReply.InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
			}(i)
		}
		wg.Wait()

		ccs := make([]*semicentral.Client, MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			ccs[i] = semicentral.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
		}

		txnIdx := 0
		wIdx := -1
		rIdx := -1
		for blkIdx := 0; blkIdx < s.NumBlks; blkIdx++ {
			numTxns := s.Blks[blkIdx]
			txns := s.Txns[txnIdx : txnIdx+numTxns]
			txnIdx += numTxns
			wg.Add(numTxns)
			for i := 0; i < numTxns; i++ {
				if txns[i] == 1 {
					// Write
					wIdx++
					go func(clIdx int, idx int) {
						defer wg.Done()
						wm := monitor.NewTimeMeasure(fmt.Sprintf("wr_%d", idx))
						// Prepare write
						data := make([]byte, 32)
						rand.Read(data)
						wr, encD, err := semicentral.NewSCWrite(data,
							readers[clIdx].Ed25519.Point, s.serverPk)
						if err != nil {
							log.Error(err)
						}
						// Add write
						_, err = ccs[clIdx].StoreData(encD, wr.DataHash)
						if err != nil {
							log.Error(err)
						}
						//storedKeys[idx] = reply.StoredKey
						wrReply, err := ccs[clIdx].AddWrite(wr,
							writers[clIdx], wCtrs[clIdx], *wDarc, wait)
						if err != nil {
							log.Error(err)
						}
						wCtrs[clIdx]++
						wp, err := ccs[clIdx].WaitProof(wrReply.
							InstanceID, time.Duration(commons.WP_INTERVAL), nil)
						if err != nil {
							log.Error(err)
						}
						if !wp.InclusionProof.Match(wrReply.InstanceID.Slice()) {
							log.Errorf("write inclusion proof does not match")
						}
						wm.Record()
					}(i, wIdx)
				} else {
					// Read
					rIdx++
					go func(clIdx int, idx int) {
						defer wg.Done()
						rm := monitor.NewTimeMeasure(fmt.Sprintf("r_%d", idx))
						modIdx := idx % MAX_TXN_CNT
						rReply, err := ccs[clIdx].AddRead(wrProofs[modIdx],
							readers[modIdx], rCtrs[modIdx], wait)
						if err != nil {
							log.Error(err)
						}
						rCtrs[modIdx]++

						rProof, err := ccs[clIdx].WaitProof(rReply.InstanceID,
							time.Duration(commons.WP_INTERVAL), nil)
						if err != nil {
							log.Error(err)
						}
						if !rProof.InclusionProof.Match(rReply.InstanceID.Slice()) {
							log.Errorf("read inclusion proof does not match")
						}

						dr, err := ccs[clIdx].Decrypt(&semicentral.SCDecryptRequest{
							Write: *wrProofs[modIdx],
							Read:  *rProof,
							Key:   storedKeys[modIdx],
						}, readers[modIdx].Ed25519.Secret)
						if err != nil {
							log.Error(err)
						}
						_, err = semicentral.RecoverData(dr.Data,
							readers[modIdx].Ed25519.Secret, dr.K, dr.C)
						rm.Record()
					}(i, rIdx)
				}
			}
			wg.Wait()
		}
	}
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	s.NumTxns = s.NumWriteTxns + s.NumReadTxns
	s.NodeCount = len(config.Roster.List)
	s.Publics = config.Roster.Publics()
	s.Txns, s.Blks, err = ReadFile(s.TxnFile, s.BlkFile)
	s.NumBlks = len(s.Blks)
	if err != nil {
		log.Error(err)
		return err
	}
	if len(s.Txns) != s.NumTxns {
		return xerrors.New("read error")
	}
	if s.ProtoName == "OTS" {
		s.Threshold = s.F + 1
		err = s.runOTS(config)
	} else if s.ProtoName == "PQOTS" {
		s.Threshold = s.F + 1
		s.VerifyThreshold = 2*s.F + 1
		err = s.runPQOTS(config)
	} else if s.ProtoName == "SC" {
		s.serverPk = config.Roster.Publics()[0]
		err = s.runSC(config)
	} else {
		log.Fatal("invalid protocol name")
	}
	return err
}
