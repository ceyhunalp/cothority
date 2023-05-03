package main

import (
	"fmt"
	"go.dedis.ch/cothority/v3/byzcoin"
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
	NumTxns         int
	MaxTxns         int
	ProtoName       string
	BlockTime       int
	NodeCount       int
	Threshold       int
	VerifyThreshold int
	Publics         []kyber.Point
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
	wait := 0
	writes := make([]*ots.Write, s.NumTxns)
	shares := make([][]*pvss.PubVerShare, s.NumTxns)
	encData := make([][]byte, s.NumTxns)
	wrReplies := make([]*ots.WriteReply, s.NumTxns)
	wrProofs := make([]*byzcoin.Proof, s.NumTxns)
	rReplies := make([]*ots.ReadReply, s.NumTxns)
	rProofs := make([]*byzcoin.Proof, s.NumTxns)

	for round := 0; round < s.Rounds; round++ {
		// Setup
		writers, wCtrs, readers, rCtrs, wDarcs := commons.CreateMultipleDarcs(s.ProtoName, s.NumTxns)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		cl := ots.NewClient(byzd.Cl)

		for i := 0; i < s.NumTxns; i++ {
			if i == s.NumTxns-1 {
				wait = 2
			}
			_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc,
				*wDarcs[i], wait)
			if err != nil {
				log.Error(err)
				return err
			}
			byzd.AdminCtr++
		}

		wait = 0
		// Prepare OTS writes
		for i := 0; i < s.NumTxns; i++ {
			sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
				s.NodeCount, s.Threshold, s.Publics, wDarcs[i].GetID())
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
				PolicyID: wDarcs[i].GetID(),
				Shares:   sh,
				Proofs:   pr,
				Publics:  s.Publics,
				CtxtHash: ctxtHash,
			}
			encData[i] = ctxt
			shares[i] = sh
		}

		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				m := monitor.NewTimeMeasure(fmt.Sprintf("write_%d", idx))
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
				m.Record()
			}(i)
		}
		wg.Wait()

		// Dummy
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

		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				m := monitor.NewTimeMeasure(fmt.Sprintf("read_%d", idx))
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
	}
	return nil
}

func (s *SimulationService) runPQOTSBurst(config *onet.SimulationConfig) error {
	wait := 0
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
		writers, wCtrs, readers, rCtrs, wDarcs := commons.CreateMultipleDarcs(s.ProtoName, s.NumTxns)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}
		cl := pqots.NewClient(byzd.Cl)

		for i := 0; i < s.NumTxns; i++ {
			_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarcs[i], 0)
			if err != nil {
				log.Error(err)
				return err
			}
			byzd.AdminCtr++
		}

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

		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				m := monitor.NewTimeMeasure(fmt.Sprintf("write_%d", idx))
				replies := cl.VerifyWriteAll(config.Roster, writes[idx], shares[idx],
					rands[idx])
				if len(replies) < s.VerifyThreshold {
					log.Errorf("not enough verifications")
				}
				sigs[idx] = make(map[int][]byte)
				for id, r := range replies {
					sigs[idx][id] = r.Sig
				}
				wrReplies[idx], err = cl.AddWrite(writes[idx],
					sigs[idx], s.VerifyThreshold, writers[idx],
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
				m.Record()
			}(i)
		}
		wg.Wait()

		// Dummy
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
			_, err = cl.DecryptKey(&pqots.PQOTSDKRequest{Roster: config.Roster,
				Threshold: s.Threshold,
				Read:      *rp,
				Write:     *wrProofs[0],
			})
			if err != nil {
				log.Error(err)
				return err
			}
		}

		wg.Add(s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			go func(idx int) {
				defer wg.Done()
				m := monitor.NewTimeMeasure(fmt.Sprintf("read_%d", idx))
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
				dkr, err := cl.DecryptKey(&pqots.PQOTSDKRequest{
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
				m.Record()
			}(i)
		}
		wg.Wait()
	}
	return nil
}

func (s *SimulationService) dummyRecords() {
	for i := s.NumTxns; i < s.MaxTxns; i++ {
		label := fmt.Sprintf("write_%d", i)
		for round := 0; round < s.Rounds; round++ {
			dummy := monitor.NewTimeMeasure(label)
			time.Sleep(1 * time.Millisecond)
			dummy.Record()
		}
		label = fmt.Sprintf("read_%d", i)
		for round := 0; round < s.Rounds; round++ {
			dummy := monitor.NewTimeMeasure(label)
			time.Sleep(1 * time.Millisecond)
			dummy.Record()
		}
	}
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	s.NodeCount = len(config.Roster.List)
	s.Publics = config.Roster.Publics()
	if s.ProtoName == "OTS" {
		s.Threshold = ((s.NodeCount - 1) / 2) + 1
		err = s.runOTSBurst(config)
	} else {
		f := (s.NodeCount - 1) / 3
		s.Threshold = f + 1
		s.VerifyThreshold = 2*f + 1
		err = s.runPQOTSBurst(config)
	}
	s.dummyRecords()
	return err
}
