package main

import (
	"bytes"
	"fmt"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso/experiments/semicentral"
	"go.dedis.ch/cothority/v3/calypso/pqots"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3/simul/monitor"
	"math/rand"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/calypso/experiments/commons"
	"go.dedis.ch/cothority/v3/calypso/ots"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

type SimulationService struct {
	onet.SimulationBFTree
	NodeCount       int
	F               int
	Threshold       int
	VerifyThreshold int
	BlockTime       int
	ProtoName       string
	NumTxns         int
	MaxTxns         int
	Publics         []kyber.Point
	serverPk        kyber.Point
}

func init() {
	onet.SimulationRegister("BurstSim", NewBurstSim)
}

func NewBurstSim(config string) (onet.Simulation, error) {
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

func (s *SimulationService) runOTSBurst(config *onet.SimulationConfig) error {
	writes := make([]*ots.Write, s.NumTxns)
	shares := make([][]*pvss.PubVerShare, s.NumTxns)
	encData := make([][]byte, s.NumTxns)
	wrReplies := make([]*ots.WriteReply, s.NumTxns)
	wrProofs := make([]*byzcoin.Proof, s.NumTxns)
	rReplies := make([]*ots.ReadReply, s.NumTxns)
	rProofs := make([]*byzcoin.Proof, s.NumTxns)

	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs, wDarc := commons.CreateMultiClientDarc(s.ProtoName, s.NumTxns)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		baseCl := ots.NewClient(byzd.Cl)

		_, err = baseCl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarc, commons.TXN_WAIT)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++

		// Prepare OTS writes
		for i := 0; i < s.NumTxns; i++ {
			sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
				s.NodeCount, s.Threshold, s.Publics, wDarc.GetID())
			if err != nil {
				log.Error(err)
				return err
			}
			data := make([]byte, 32)
			rand.Read(data)
			ctxt, ctxtHash, err := ots.Encrypt(cothority.Suite, secret, data)
			if err != nil {
				log.Error(err)
				return err
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

		ccs := make([]*ots.Client, s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			ccs[i] = ots.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
		}

		wait := 0
		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				wm := monitor.NewTimeMeasure(fmt.Sprintf("wr_%d", idx))
				wrReplies[idx], err = ccs[idx].AddWrite(writes[idx],
					writers[idx], wCtrs[idx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++

				wrProofs[idx], err = ccs[idx].WaitProof(wrReplies[idx].InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !wrProofs[idx].InclusionProof.Match(wrReplies[idx].InstanceID.Slice()) {
					log.Errorf("write inclusion proof does not match")
				}
				wm.Record()

				rm := monitor.NewTimeMeasure(fmt.Sprintf("r_%d", idx))
				rReplies[idx], err = ccs[idx].AddRead(wrProofs[idx], readers[idx],
					rCtrs[idx], wait)
				if err != nil {
					log.Error(err)
				}
				rCtrs[idx]++

				rProofs[idx], err = ccs[idx].WaitProof(rReplies[idx].InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !rProofs[idx].InclusionProof.Match(rReplies[idx].InstanceID.Slice()) {
					log.Errorf("read inclusion proof does not match")
				}

				dkr, err := ccs[idx].DecryptKey(&ots.OTSDKRequest{
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
				rm.Record()
			}(i)
		}
		wg.Wait()

		//for i := 0; i < s.NumTxns; i++ {
		//	err := ccs[i].Close()
		//	if err != nil {
		//		log.Error(err)
		//	}
		//}
	}
	return nil
}

func (s *SimulationService) runPQOTSBurst(config *onet.SimulationConfig) error {
	encData := make([][]byte, s.NumTxns)
	writes := make([]*pqots.Write, s.NumTxns)
	shares := make([][]*share.PriShare, s.NumTxns)
	rands := make([][][]byte, s.NumTxns)
	sigs := make([]map[int][]byte, s.NumTxns)
	wrReplies := make([]*pqots.WriteReply, s.NumTxns)
	wrProofs := make([]*byzcoin.Proof, s.NumTxns)
	rReplies := make([]*pqots.ReadReply, s.NumTxns)
	rProofs := make([]*byzcoin.Proof, s.NumTxns)

	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs, wDarc := commons.CreateMultiClientDarc(s.ProtoName, s.NumTxns)
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

		// Generate writes and collect signatures
		for i := 0; i < s.NumTxns; i++ {
			var commitments [][]byte
			var err error
			poly := pqots.GenerateSSPoly(s.Threshold)
			shares[i], rands[i], commitments, err = pqots.GenerateCommitments(poly,
				s.NodeCount)
			if err != nil {
				log.Error(err)
				return err
			}
			ticket := make([]byte, 32)
			rand.Read(ticket)
			ctxt, ctxtHash, err := pqots.Encrypt(poly.Secret(), ticket)
			writes[i] = &pqots.Write{Commitments: commitments,
				Publics:  s.Publics,
				CtxtHash: ctxtHash}
			encData[i] = ctxt
		}

		ccs := make([]*pqots.Client, s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			ccs[i] = pqots.NewClient(byzcoin.NewClient(byzd.Cl.ID,
				byzd.Cl.Roster))
		}

		wait := 0
		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				wm := monitor.NewTimeMeasure(fmt.Sprintf("wr_%d", idx))
				replies := ccs[idx].VerifyWriteAll(config.Roster, writes[idx],
					shares[idx], rands[idx])
				if len(replies) < s.VerifyThreshold {
					log.Errorf("not enough verifications")
				}
				sigs[idx] = make(map[int][]byte)
				for id, r := range replies {
					sigs[idx][id] = r.Sig
				}

				wrReplies[idx], err = ccs[idx].AddWrite(writes[idx],
					sigs[idx], s.VerifyThreshold, writers[idx],
					wCtrs[idx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++

				wrProofs[idx], err = ccs[idx].WaitProof(wrReplies[idx].InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !wrProofs[idx].InclusionProof.Match(wrReplies[idx].InstanceID.Slice()) {
					log.Errorf("write inclusion proof does not match")
				}
				wm.Record()

				rm := monitor.NewTimeMeasure(fmt.Sprintf("r_%d", idx))
				rReplies[idx], err = ccs[idx].AddRead(wrProofs[idx], readers[idx],
					rCtrs[idx], wait)
				if err != nil {
					log.Error(err)
				}
				rCtrs[idx]++

				rProofs[idx], err = ccs[idx].WaitProof(rReplies[idx].InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !rProofs[idx].InclusionProof.Match(rReplies[idx].InstanceID.Slice()) {
					log.Errorf("read inclusion proof does not match")
				}

				dkr, err := ccs[idx].DecryptKey(&pqots.PQOTSDKRequest{
					Roster:    config.Roster,
					Threshold: s.Threshold,
					Read:      *rProofs[idx],
					Write:     *wrProofs[idx],
				})
				if err != nil {
					log.Error(err)
				}
				decShares := pqots.ElGamalDecrypt(cothority.Suite,
					readers[idx].Ed25519.Secret, dkr.Reencryptions)
				recSecret, err := share.RecoverSecret(cothority.Suite, decShares,
					s.Threshold, s.NodeCount)
				if err != nil {
					log.Error(err)
				}
				_, err = pqots.Decrypt(recSecret, encData[idx])
				if err != nil {
					log.Error(err)
				}
				rm.Record()
			}(i)
		}
		wg.Wait()
	}
	return nil
}

func (s *SimulationService) runSCBurst(config *onet.SimulationConfig) error {
	//TODO: Remove ptData
	ptData := make([][]byte, s.NumTxns)
	encData := make([][]byte, s.NumTxns)
	storedKeys := make([]string, s.NumTxns)
	writes := make([]*semicentral.SCWrite, s.NumTxns)
	wrReplies := make([]*semicentral.WriteReply, s.NumTxns)
	wrProofs := make([]*byzcoin.Proof, s.NumTxns)
	rReplies := make([]*semicentral.ReadReply, s.NumTxns)
	rProofs := make([]*byzcoin.Proof, s.NumTxns)

	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs, wDarc := commons.CreateMultiClientDarc(s.ProtoName, s.NumTxns)
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

		for i := 0; i < s.NumTxns; i++ {
			data := make([]byte, 32)
			rand.Read(data)
			writes[i], encData[i], err = semicentral.NewSCWrite(data,
				readers[i].Ed25519.Point, s.serverPk)
			if err != nil {
				return err
			}
			ptData[i] = data
		}

		ccs := make([]*semicentral.Client, s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			ccs[i] = semicentral.NewClient(byzcoin.NewClient(byzd.Cl.ID,
				byzd.Cl.Roster))
		}

		wait := 0
		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				wm := monitor.NewTimeMeasure(fmt.Sprintf("wr_%d", idx))
				reply, err := ccs[idx].StoreData(encData[idx], writes[idx].DataHash)
				if err != nil {
					log.Error(err)
				}
				storedKeys[idx] = reply.StoredKey

				wrReplies[idx], err = ccs[idx].AddWrite(writes[idx], writers[idx],
					wCtrs[idx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[idx]++

				wrProofs[idx], err = ccs[idx].WaitProof(wrReplies[idx].InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !wrProofs[idx].InclusionProof.Match(wrReplies[idx].InstanceID.Slice()) {
					log.Errorf("write inclusion proof does not match")
				}
				wm.Record()

				rm := monitor.NewTimeMeasure(fmt.Sprintf("r_%d", idx))
				rReplies[idx], err = ccs[idx].AddRead(wrProofs[idx], readers[idx], rCtrs[idx], wait)
				if err != nil {
					log.Error(err)
				}
				rCtrs[idx]++

				rProofs[idx], err = ccs[idx].WaitProof(rReplies[idx].InstanceID,
					time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !rProofs[idx].InclusionProof.Match(rReplies[idx].InstanceID.Slice()) {
					log.Errorf("read inclusion proof does not match")
				}

				dr, err := ccs[idx].Decrypt(&semicentral.DecryptRequest{
					Write: *wrProofs[idx],
					Read:  *rProofs[idx],
					Key:   storedKeys[idx],
				}, readers[idx].Ed25519.Secret)
				if err != nil {
					log.Error(err)
				}
				data, err := semicentral.RecoverData(dr.Data, readers[idx].Ed25519.Secret, dr.K, dr.C)
				log.Info("Recovered?", bytes.Equal(data, ptData[idx]))
				rm.Record()
			}(i)
		}
		wg.Wait()

	}
	return nil
}

func (s *SimulationService) dummyRecords() {
	for i := s.NumTxns; i < s.MaxTxns; i++ {
		for round := 0; round < s.Rounds; round++ {
			label := fmt.Sprintf("wr_%d", i)
			d1 := monitor.NewTimeMeasure(label)
			time.Sleep(1 * time.Millisecond)
			d1.Record()
			label = fmt.Sprintf("r_%d", i)
			d2 := monitor.NewTimeMeasure(label)
			time.Sleep(1 * time.Millisecond)
			d2.Record()
		}
	}
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	log.Info("Starting", s.ProtoName, s.NumTxns)
	s.NodeCount = len(config.Roster.List)
	s.Publics = config.Roster.Publics()
	if s.ProtoName == "OTS" {
		s.Threshold = s.F + 1
		err = s.runOTSBurst(config)
	} else if s.ProtoName == "PQOTS" {
		s.Threshold = s.F + 1
		s.VerifyThreshold = 2*s.F + 1
		err = s.runPQOTSBurst(config)
	} else if s.ProtoName == "SC" {
		s.serverPk = config.Roster.Publics()[0]
		err = s.runSCBurst(config)
	} else {
		log.Fatal("invalid protocol name")
	}
	s.dummyRecords()
	return err
}
