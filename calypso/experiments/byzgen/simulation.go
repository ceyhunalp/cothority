package main

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso/experiments/commons"
	"go.dedis.ch/cothority/v3/calypso/ots"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
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
	ProtoName       string
	BlockTime       int
	NodeCount       int
	Threshold       int
	VerifyThreshold int
	Publics         []kyber.Point

	TxnFile      string
	Txns         []int
	NumTxns      int
	NumWriteTxns int
	NumReadTxns  int

	BlkFile string
	Blks    []int
	NumBlks int
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

func (s *SimulationService) prepareOTSWrites(wDarcs []*darc.Darc) ([]*ots.
	Write, [][]*pvss.PubVerShare, [][]byte, error) {
	writes := make([]*ots.Write, s.NumWriteTxns)
	shares := make([][]*pvss.PubVerShare, s.NumWriteTxns)
	encData := make([][]byte, s.NumWriteTxns)
	for i := 0; i < MAX_TXN_CNT; i++ {
		sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
			s.NodeCount, s.Threshold, s.Publics, wDarcs[i].GetID())
		if err != nil {
			return nil, nil, nil, err
		}
		data := make([]byte, 32)
		rand.Read(data)
		ctxt, ctxtHash, err := ots.Encrypt(cothority.Suite, secret, data)
		if err != nil {
			return nil, nil, nil, err
		}
		writes[i] = &ots.Write{
			PolicyID: wDarcs[i].GetID(),
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
	wrReplies := make([]*ots.WriteReply, MAX_TXN_CNT)
	wrProofs := make([]*byzcoin.Proof, MAX_TXN_CNT)
	rReplies := make([]*ots.ReadReply, MAX_TXN_CNT)
	rProofs := make([]*byzcoin.Proof, MAX_TXN_CNT)
	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs, wDarcs := commons.CreateMultipleDarcs(s.ProtoName, MAX_TXN_CNT)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		cl := ots.NewClient(byzd.Cl)

		for i := 0; i < MAX_TXN_CNT; i++ {
			_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarcs[i], 0)
			if err != nil {
				log.Error(err)
				return err
			}
			byzd.AdminCtr++
		}
		writes, shares, encData, err := s.prepareOTSWrites(wDarcs)
		if err != nil {
			return err
		}
		var wg sync.WaitGroup
		wg.Add(MAX_TXN_CNT)
		for i := 0; i < MAX_TXN_CNT; i++ {
			go func(idx int) {
				defer wg.Done()
				wrReplies[idx], err = cl.AddWrite(writes[idx], writers[idx],
					wCtrs[idx], *wDarcs[idx], wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++
				wrProofs[idx], err = cl.WaitProof(wrReplies[idx].InstanceID,
					time.Duration(s.BlockTime), nil)
				if err != nil {
					log.Error(err)
				}
				if !wrProofs[idx].InclusionProof.Match(wrReplies[idx].InstanceID.Slice()) {
					log.Errorf("write inclusion proof does not match")
				}
			}(i)
		}
		wg.Wait()

		// BEGIN_DUMMY
		if round == 0 {
			rep, err := cl.AddRead(wrProofs[0], readers[0], rCtrs[0], wait)
			if err != nil {
				log.Error(err)
				return err
			}
			rCtrs[0]++
			rp, err := cl.WaitProof(rep.InstanceID, time.Duration(s.BlockTime), nil)
			if err != nil {
				log.Error(err)
				return err
			}
			_, err = cl.DecryptKey(&ots.OTSDKRequest{Roster: config.Roster,
				Threshold: s.Threshold,
				Read:      *rp,
				Write:     *wrProofs[0],
			})
			if err != nil {
				log.Error(err)
				return err
			}
		}
		// END_DUMMY

		readCount := 0
		txnIdx := 0
		for blkIdx := 0; blkIdx < s.NumBlks; blkIdx++ {
			numTxns := s.Blks[blkIdx]
			txns := s.Txns[txnIdx : txnIdx+numTxns]
			txnIdx += numTxns
			wIdx := 0
			rIdx := 0
			wg.Add(numTxns)
			m := monitor.NewTimeMeasure(fmt.Sprintf("blk_%d", blkIdx))
			for i := 0; i < numTxns; i++ {
				if txns[i] == 1 {
					// Write
					go func(idx int) {
						defer wg.Done()
						reply, err := cl.AddWrite(writes[idx], writers[idx],
							wCtrs[idx], *wDarcs[idx], wait)
						if err != nil {
							log.Error(err)
						}
						wCtrs[idx]++
						pr, err := cl.WaitProof(reply.InstanceID, time.Duration(s.BlockTime), nil)
						if err != nil {
							log.Error(err)
						}
						if !pr.InclusionProof.Match(reply.InstanceID.Slice()) {
							log.Errorf("write inclusion proof does not match")
						}
					}(wIdx)
					wIdx++
				} else {
					// Read
					go func(idx int) {
						defer wg.Done()
						rReplies[idx], err = cl.AddRead(wrProofs[idx], readers[idx],
							rCtrs[idx], wait)
						if err != nil {
							log.Error(err)
						}
						rCtrs[idx]++
						rProofs[idx], err = cl.WaitProof(rReplies[idx].InstanceID,
							time.Duration(s.BlockTime), nil)
						if err != nil {
							log.Error(err)
						}
						if !rProofs[idx].InclusionProof.Match(rReplies[idx].InstanceID.Slice()) {
							log.Errorf("read inclusion proof does not match")
						}
					}(rIdx)
					rIdx++
				}
			}
			wg.Wait()
			m.Record()

			wg.Add(rIdx)
			for i := 0; i < rIdx; i++ {
				go func(idx int) {
					defer wg.Done()
					m := monitor.NewTimeMeasure(fmt.Sprintf("read_%d_dec",
						readCount+i))
					dkr, err := cl.DecryptKey(&ots.OTSDKRequest{
						Roster:    config.Roster,
						Threshold: s.Threshold,
						Read:      *rProofs[idx],
						Write:     *wrProofs[idx],
					})
					if err != nil {
						log.Error(err)
					}
					var keys []kyber.Point
					var encShares []*pvss.PubVerShare
					g := cothority.Suite.Point().Base()
					decShares := ots.ElGamalDecrypt(cothority.Suite, readers[idx].Ed25519.Secret,
						dkr.Reencryptions)
					for _, ds := range decShares {
						keys = append(keys, s.Publics[ds.S.I])
						encShares = append(encShares, shares[idx][ds.S.I])
					}
					recSecret, err := pvss.RecoverSecret(cothority.Suite, g, keys, encShares,
						decShares, s.Threshold, s.NodeCount)
					if err != nil {
						log.Error(err)
					}
					_, err = ots.Decrypt(recSecret, encData[idx])
					if err != nil {
						log.Error(err)
					}
					m.Record()
				}(i)
			}
			wg.Wait()
			readCount += rIdx
		}
	}
	return nil
}

func (s *SimulationService) runPQOTS(config *onet.SimulationConfig) error {
	//wait := 0
	//writes, err := s.preparePQOTSWrites()
	return nil

}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	s.NumTxns = s.NumWriteTxns + s.NumReadTxns
	s.NodeCount = len(config.Roster.List)
	s.Publics = config.Roster.Publics()
	s.Txns, s.Blks, err = ReadFile(s.TxnFile, s.BlkFile)
	if err != nil {
		log.Error(err)
		return err
	}

	if len(s.Txns) != s.NumTxns {
		return xerrors.New("read error")
	}

	if s.ProtoName == "OTS" {
		s.Threshold = ((s.NodeCount - 1) / 2) + 1
		err = s.runOTS(config)
	} else if s.ProtoName == "PQOTS" {
		f := (s.NodeCount - 1) / 3
		s.Threshold = f + 1
		s.VerifyThreshold = 2*f + 1
		err = s.runPQOTS(config)
	} else {
		log.Fatal("invalid protocol name")
	}
	return err
}
