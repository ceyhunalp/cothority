package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso/experiments/lottery/tournament"
	"go.dedis.ch/cothority/v3/calypso/pqots"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3/simul/monitor"
	"golang.org/x/xerrors"
	"math"
	"math/rand"
	"sort"
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
	ProtoName       string
	BlockTime       int
	NodeCount       int
	Threshold       int
	VerifyThreshold int
	Publics         []kyber.Point
}

func init() {
	onet.SimulationRegister("LotterySim", NewLotterySim)
}

func NewLotterySim(config string) (onet.Simulation, error) {
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

func (s *SimulationService) runOTSLottery(config *onet.SimulationConfig) error {
	var err error
	shares := make([][]*pvss.PubVerShare, s.NumTxns)
	encTickets := make([][]byte, s.NumTxns)
	decTickets := make([][]byte, s.NumTxns)
	writes := make([]*ots.Write, s.NumTxns)
	wrReplies := make([]*ots.WriteReply, s.NumTxns)
	wrProofs := make([]*byzcoin.Proof, s.NumTxns)
	rReplies := make([]*ots.ReadReply, s.NumTxns)
	rProofs := make([]*byzcoin.Proof, s.NumTxns)
	wait := 0

	// Setup
	writers, wCtrs, readers, rCtrs, wDarcs := commons.CreateMultipleDarcs(s.ProtoName, s.NumTxns)

	byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
	if err != nil {
		return err
	}
	cl := ots.NewClient(byzd.Cl)

	for j := 0; j < s.NumTxns; j++ {
		_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarcs[j], 0)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++
	}

	// Prepare OTS writes
	for j := 0; j < s.NumTxns; j++ {
		sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
			s.NodeCount, s.Threshold, s.Publics, wDarcs[j].GetID())
		if err != nil {
			log.Error(err)
			return err
		}
		ticket := make([]byte, 32)
		rand.Read(ticket)
		ctxt, ctxtHash, err := ots.Encrypt(cothority.Suite, secret, ticket)
		if err != nil {
			log.Error(err)
			return err
		}
		writes[j] = &ots.Write{
			PolicyID: wDarcs[j].GetID(),
			Shares:   sh,
			Proofs:   pr,
			Publics:  s.Publics,
			CtxtHash: ctxtHash,
		}
		encTickets[j] = ctxt
		shares[j] = sh
	}

	var wg sync.WaitGroup
	wg.Add(s.NumTxns)
	for j := 0; j < s.NumTxns; j++ {
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
		}(j)
	}
	wg.Wait()

	for i := 0; i < s.Rounds; i++ {
		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		rm := monitor.NewTimeMeasure("add_read")
		for j := 0; j < s.NumTxns; j++ {
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
			}(j)
		}
		wg.Wait()
		rm.Record()

		if i == 0 {
			_, err = cl.DecryptKey(&ots.OTSDKRequest{
				Roster:    config.Roster,
				Threshold: s.Threshold,
				Read:      *rProofs[0],
				Write:     *wrProofs[0],
			})
			if err != nil {
				log.Error(err)
				return err
			}
		}

		d := monitor.NewTimeMeasure("decrypt")
		for j := 0; j < s.NumTxns; j++ {
			dkr, err := cl.DecryptKey(&ots.OTSDKRequest{
				Roster:    config.Roster,
				Threshold: s.Threshold,
				Read:      *rProofs[j],
				Write:     *wrProofs[j],
			})
			if err != nil {
				log.Error(err)
				return err
			}
			var keys []kyber.Point
			var encShares []*pvss.PubVerShare
			g := cothority.Suite.Point().Base()
			decShares := ots.ElGamalDecrypt(cothority.Suite, readers[j].Ed25519.Secret,
				dkr.Reencryptions)
			for _, ds := range decShares {
				keys = append(keys, s.Publics[ds.S.I])
				encShares = append(encShares, shares[j][ds.S.I])
			}
			recSecret, err := pvss.RecoverSecret(cothority.Suite, g, keys, encShares,
				decShares, s.Threshold, s.NodeCount)
			if err != nil {
				log.Error(err)
				return err
			}
			decTickets[j], err = ots.Decrypt(recSecret, encTickets[j])
			if err != nil {
				log.Error(err)
				return err
			}
		}
		d.Record()

		w := monitor.NewTimeMeasure("find_winner")
		result := make([]byte, 32)
		for j := 0; j < s.NumTxns; j++ {
			commons.SafeXORBytes(result, result, decTickets[i])
		}
		_ = int(result[31]) % s.NumTxns
		w.Record()
		//log.Info("Winner:", int(result[31])%s.NumTxns)
	}
	return nil
}

func (s *SimulationService) runPQOTSLottery(config *onet.SimulationConfig) error {
	var err error
	encTickets := make([][]byte, s.NumTxns)
	decTickets := make([][]byte, s.NumTxns)
	writes := make([]*pqots.Write, s.NumTxns)
	sigs := make([]map[int][]byte, s.NumTxns)
	wrReplies := make([]*pqots.WriteReply, s.NumTxns)
	wrProofs := make([]*byzcoin.Proof, s.NumTxns)
	rReplies := make([]*pqots.ReadReply, s.NumTxns)
	rProofs := make([]*byzcoin.Proof, s.NumTxns)
	wait := 0

	// Setup
	writers, wCtrs, readers, rCtrs, wDarcs := commons.CreateMultipleDarcs(s.ProtoName, s.NumTxns)
	byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
	if err != nil {
		return err
	}
	cl := pqots.NewClient(byzd.Cl)

	for j := 0; j < s.NumTxns; j++ {
		_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarcs[j], 0)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++
	}

	// Generate writes and collect signatures
	for j := 0; j < s.NumTxns; j++ {
		poly := pqots.GenerateSSPoly(s.Threshold)
		shares, rands, commitments, err := pqots.GenerateCommitments(poly,
			s.NodeCount)
		if err != nil {
			log.Error(err)
			return err
		}
		ticket := make([]byte, 32)
		rand.Read(ticket)
		ctxt, ctxtHash, err := pqots.Encrypt(poly.Secret(), ticket)
		writes[j] = &pqots.Write{Commitments: commitments,
			Publics:  s.Publics,
			CtxtHash: ctxtHash}
		replies := cl.VerifyWriteAll(config.Roster, writes[j], shares,
			rands)
		if len(replies) < s.VerifyThreshold {
			log.Errorf("not enough verifications")
			return xerrors.New("not enough verifications")
		}
		sigs[j] = make(map[int][]byte)
		for id, r := range replies {
			sigs[j][id] = r.Sig
		}
		encTickets[j] = ctxt
	}

	// Add write txns
	var wg sync.WaitGroup
	wg.Add(s.NumTxns)
	for j := 0; j < s.NumTxns; j++ {
		go func(idx int) {
			defer wg.Done()
			wrReplies[idx], err = cl.AddWrite(writes[idx], sigs[idx],
				s.VerifyThreshold, writers[idx], wCtrs[idx], *wDarcs[idx], wait)
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
		}(j)
	}
	wg.Wait()

	for i := 0; i < s.Rounds; i++ {
		// Add read txns
		var wg sync.WaitGroup
		wg.Add(s.NumTxns)
		rm := monitor.NewTimeMeasure("add_read")
		for j := 0; j < s.NumTxns; j++ {
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
			}(j)
		}
		wg.Wait()
		rm.Record()

		if i == 0 {
			_, err = cl.DecryptKey(&pqots.PQOTSDKRequest{
				Roster:    config.Roster,
				Threshold: s.Threshold,
				Read:      *rProofs[0],
				Write:     *wrProofs[0],
			})
			if err != nil {
				log.Error(err)
				return err
			}
		}

		d := monitor.NewTimeMeasure("decrypt")
		for j := 0; j < s.NumTxns; j++ {
			dkr, err := cl.DecryptKey(&pqots.PQOTSDKRequest{
				Roster:    config.Roster,
				Threshold: s.Threshold,
				Read:      *rProofs[j],
				Write:     *wrProofs[j],
			})
			if err != nil {
				log.Error(err)
				return err
			}
			decShares := pqots.ElGamalDecrypt(cothority.Suite,
				readers[j].Ed25519.Secret, dkr.Reencryptions)
			recSecret, err := share.RecoverSecret(cothority.Suite, decShares,
				s.Threshold, s.NodeCount)
			if err != nil {
				log.Error(err)
				return err
			}
			decTickets[j], err = pqots.Decrypt(recSecret, encTickets[j])
			if err != nil {
				log.Error(err)
				return err
			}
		}
		d.Record()

		w := monitor.NewTimeMeasure("find_winner")
		result := make([]byte, 32)
		for j := 0; j < s.NumTxns; j++ {
			commons.SafeXORBytes(result, result, decTickets[i])
		}
		_ = int(result[31]) % s.NumTxns
		w.Record()
		//log.Info("Winner:", int(result[31])%s.NumTxns)
	}
	return nil
}

func (s *SimulationService) runTournamentLottery(config *onet.SimulationConfig) error {
	wait := 0
	for r := 0; r < s.Rounds; r++ {
		writers, wCtrs, wDarcs := tournament.CreateMultipleDarcs(s.NumTxns)

		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}

		cl := tournament.NewClient(byzd.Cl)
		for i := 0; i < s.NumTxns; i++ {
			_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarcs[i], 0)
			if err != nil {
				log.Error(err)
				return err
			}
			byzd.AdminCtr++
		}

		lotteryRounds := int(math.Ceil(math.Log2(float64(s.NumTxns))))
		numActvTxns := s.NumTxns
		participants := make([]int, s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			participants[i] = 1
		}
		isOdd := false
		for round := 0; round < lotteryRounds; round++ {
			activeParticipants := tournament.GetActiveParticipants(participants)
			if numActvTxns%2 != 0 {
				numActvTxns -= 1
				isOdd = true
			}
			lotteryData := make([]*tournament.LotteryData, numActvTxns)
			commitReplies := make([]*tournament.TransactionReply, numActvTxns)
			for i := 0; i < numActvTxns; i++ {
				origIdx := activeParticipants[i]
				lotteryData[i] = tournament.CreateLotteryData()
				cKey := fmt.Sprintf("commit_%d_%d", round, origIdx)
				ds := &tournament.DataStore{Data: lotteryData[i].Commitment,
					Index: origIdx}
				commitReplies[i], err = cl.AddTransaction(ds, cKey,
					writers[origIdx], wCtrs[origIdx], *wDarcs[origIdx], wait)
				//log.Infof("Commit for %d: %x", origIdx, ds.Data)
				if err != nil {
					log.Errorf("adding txn: %v", err)
					return err
				}
				wCtrs[origIdx]++
			}

			commitProofs := make([]*byzcoin.Proof, numActvTxns)
			for i := 0; i < numActvTxns; i++ {
				commitProofs[i], err = cl.WaitProof(commitReplies[i].
					InstanceID, time.Duration(s.BlockTime), nil)
				if err != nil {
					log.Error(err)
					return err
				}
				if !commitProofs[i].InclusionProof.Match(commitReplies[i].InstanceID.Slice()) {
					log.Errorf("commit inclusion proof does not match")
					return err
				}
			}

			m := monitor.NewTimeMeasure("open")
			openReplies := make([]*tournament.TransactionReply, numActvTxns)
			for i := 0; i < numActvTxns; i++ {
				origIdx := activeParticipants[i]
				ds := &tournament.DataStore{Data: lotteryData[i].Secret, Index: origIdx}
				oKey := fmt.Sprintf("open_%d_%d", round, origIdx)
				openReplies[i], err = cl.AddTransaction(ds, oKey,
					writers[origIdx], wCtrs[origIdx], *wDarcs[origIdx], wait)
				if err != nil {
					log.Error(err)
					return err
				}
				//log.Infof("Open for %d: %x", origIdx, ds.Data)
				wCtrs[origIdx]++
			}

			openProofs := make([]*byzcoin.Proof, numActvTxns)
			for i := 0; i < numActvTxns; i++ {
				openProofs[i], err = cl.WaitProof(openReplies[i].
					InstanceID, time.Duration(s.BlockTime), nil)
				if err != nil {
					log.Error(err)
					return err
				}
				if !openProofs[i].InclusionProof.Match(openReplies[i].InstanceID.Slice()) {
					log.Errorf("open inclusion proof does not match")
					return err
				}
			}

			commits := make([]*tournament.DataStore, numActvTxns)
			opens := make([]*tournament.DataStore, numActvTxns)
			for i := 0; i < numActvTxns; i++ {
				commits[i], err = tournament.RecoverData(commitProofs[i])
				if err != nil {
					log.Error(err)
					return err
				}
				opens[i], err = tournament.RecoverData(openProofs[i])
				if err != nil {
					log.Error(err)
					return err
				}
			}

			sort.Slice(commits, func(i, j int) bool {
				return commits[i].Index < commits[j].Index
			})
			sort.Slice(opens, func(i, j int) bool {
				return opens[i].Index < opens[j].Index
			})

			var winnerList []int
			for i := 0; i < numActvTxns; {
				lSecret := opens[i].Data
				rSecret := opens[i+1].Data
				lHash := sha256.Sum256(lSecret[:])
				rHash := sha256.Sum256(rSecret[:])
				if bytes.Compare(lHash[:], commits[i].Data[:]) != 0 {
					log.Lvl1("Digests do not match - winner is", i+1)
					winnerList = append(winnerList, i+1)
				} else {
					if bytes.Compare(rHash[:], commits[i+1].Data[:]) != 0 {
						log.Lvl1("Digests do not match - winner is", i)
						winnerList = append(winnerList, i)
					} else {
						result := make([]byte, 32)
						commons.SafeXORBytes(result, lSecret[:], rSecret[:])
						lastDigit := int(result[31]) % 2
						if lastDigit == 0 {
							winnerList = append(winnerList, opens[i].Index)
						} else {
							winnerList = append(winnerList, opens[i+1].Index)
						}
					}
				}
				i += 2
			}
			if isOdd {
				winnerList = append(winnerList, activeParticipants[numActvTxns])
				numActvTxns += 1
			}
			numActvTxns = int(math.Ceil(float64(numActvTxns) / 2))
			isOdd = false
			tournament.OrganizeList(participants, winnerList)
			m.Record()
		}
	}
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	s.NodeCount = len(config.Roster.List)
	s.Publics = config.Roster.Publics()
	if s.ProtoName == "OTS" {
		log.Info("OTS:", s.NumTxns)
		s.Threshold = ((s.NodeCount - 1) / 2) + 1
		err = s.runOTSLottery(config)
	} else if s.ProtoName == "PQOTS" {
		log.Info("PQOTS", s.NumTxns)
		f := (s.NodeCount - 1) / 3
		s.Threshold = f + 1
		s.VerifyThreshold = 2*f + 1
		err = s.runPQOTSLottery(config)
	} else if s.ProtoName == "Tournament" {
		log.Info("Tournament", s.NumTxns)
		err = s.runTournamentLottery(config)
	} else {
		log.Fatal("invalid protocol name")
	}
	return err
}
