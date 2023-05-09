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
	NodeCount       int
	F               int
	Threshold       int
	VerifyThreshold int
	BlockTime       int
	ProtoName       string
	NumTxns         int
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
	for j := 0; j < s.NumTxns; j++ {
		sh, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
			s.NodeCount, s.Threshold, s.Publics, wDarc.GetID())
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
			PolicyID: wDarc.GetID(),
			Shares:   sh,
			Proofs:   pr,
			Publics:  s.Publics,
			CtxtHash: ctxtHash,
		}
		encTickets[j] = ctxt
		shares[j] = sh
	}

	wait := 0
	var wg sync.WaitGroup
	wg.Add(s.NumTxns)
	for j := 0; j < s.NumTxns; j++ {
		go func(idx int) {
			defer wg.Done()
			cl := ots.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
			wrReplies[idx], err = cl.AddWrite(writes[idx], writers[idx],
				wCtrs[idx], *wDarc, wait)
			if err != nil {
				log.Error(err)
			}
			wCtrs[idx]++
			wrProofs[idx], err = cl.WaitProof(wrReplies[idx].InstanceID,
				time.Duration(commons.WP_INTERVAL), nil)
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
		rm := monitor.NewTimeMeasure("read")
		for idx := 0; idx < s.NumTxns; idx++ {
			rReplies[idx], err = baseCl.AddRead(wrProofs[idx], readers[idx],
				rCtrs[idx], wait)
			if err != nil {
				log.Error(err)
			}
			rCtrs[idx]++
		}
		for idx := 0; idx < s.NumTxns; idx++ {
			rProofs[idx], err = baseCl.WaitProof(rReplies[idx].InstanceID,
				time.Duration(commons.WP_INTERVAL), nil)
			if err != nil {
				log.Error(err)
			}
			if !rProofs[idx].InclusionProof.Match(rReplies[idx].InstanceID.Slice()) {
				log.Errorf("read inclusion proof does not match")
			}
		}
		rm.Record()

		_, err = baseCl.DecryptKey(&ots.OTSDKRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Read:      *rProofs[0],
			Write:     *wrProofs[0],
		})
		if err != nil {
			log.Error(err)
			return err
		}

		d := monitor.NewTimeMeasure("dec")
		for idx := 0; idx < s.NumTxns; idx++ {
			dkr, err := baseCl.DecryptKey(&ots.OTSDKRequest{
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
			decTickets[idx], err = ots.Decrypt(recSecret, encTickets[idx])
			if err != nil {
				log.Error(err)
			}
		}
		result := make([]byte, 32)
		for j := 0; j < s.NumTxns; j++ {
			commons.SafeXORBytes(result, result, decTickets[i])
		}
		_ = int(result[31]) % s.NumTxns
		d.Record()
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

	// Setup
	writers, wCtrs, readers, rCtrs, wDarc := commons.CreateMultiClientDarc(s.
		ProtoName, s.NumTxns)
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
		replies := baseCl.VerifyWriteAll(config.Roster, writes[j], shares,
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
	wait := 0
	var wg sync.WaitGroup
	wg.Add(s.NumTxns)
	for j := 0; j < s.NumTxns; j++ {
		go func(idx int) {
			defer wg.Done()
			cl := pqots.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
			wrReplies[idx], err = cl.AddWrite(writes[idx], sigs[idx],
				s.VerifyThreshold, writers[idx], wCtrs[idx], *wDarc, wait)
			if err != nil {
				log.Error(err)
			}
			wCtrs[idx]++
			wrProofs[idx], err = cl.WaitProof(wrReplies[idx].InstanceID,
				time.Duration(commons.WP_INTERVAL), nil)
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
		rm := monitor.NewTimeMeasure("read")
		for idx := 0; idx < s.NumTxns; idx++ {
			rReplies[idx], err = baseCl.AddRead(wrProofs[idx], readers[idx],
				rCtrs[idx], wait)
			if err != nil {
				log.Error(err)
			}
			rCtrs[idx]++
			rProofs[idx], err = baseCl.WaitProof(rReplies[idx].InstanceID,
				time.Duration(commons.WP_INTERVAL), nil)
			if err != nil {
				log.Error(err)
			}
			if !rProofs[idx].InclusionProof.Match(rReplies[idx].InstanceID.Slice()) {
				log.Errorf("read inclusion proof does not match")
			}
		}
		rm.Record()

		_, err = baseCl.DecryptKey(&pqots.PQOTSDKRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Read:      *rProofs[0],
			Write:     *wrProofs[0],
		})
		if err != nil {
			log.Error(err)
			return err
		}

		d := monitor.NewTimeMeasure("dec")
		for idx := 0; idx < s.NumTxns; idx++ {
			dkr, err := baseCl.DecryptKey(&pqots.PQOTSDKRequest{
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
			decTickets[idx], err = pqots.Decrypt(recSecret, encTickets[idx])
			if err != nil {
				log.Error(err)
			}
		}
		result := make([]byte, 32)
		for j := 0; j < s.NumTxns; j++ {
			commons.SafeXORBytes(result, result, decTickets[i])
		}
		_ = int(result[31]) % s.NumTxns
		d.Record()
	}
	return nil
}

func (s *SimulationService) runTournamentLottery(config *onet.SimulationConfig) error {
	wait := 0
	for r := 0; r < s.Rounds; r++ {
		writers, wCtrs, wDarc := tournament.CreateMultiClientDarc(s.NumTxns)
		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
		if err != nil {
			return err
		}

		baseCl := tournament.NewClient(byzd.Cl)
		_, err = baseCl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc,
			*wDarc, commons.TXN_WAIT)
		if err != nil {
			log.Error(err)
			return err
		}
		byzd.AdminCtr++

		lotteryRounds := int(math.Ceil(math.Log2(float64(s.NumTxns))))
		numActvTxns := s.NumTxns
		participants := make([]int, s.NumTxns)
		for i := 0; i < s.NumTxns; i++ {
			participants[i] = 1
		}
		isOdd := false
		wait = 0
		for round := 0; round < lotteryRounds; round++ {
			activeParticipants := tournament.GetActiveParticipants(participants)
			if numActvTxns%2 != 0 {
				numActvTxns -= 1
				isOdd = true
			}
			lotteryData := make([]*tournament.LotteryData, numActvTxns)
			commitReplies := make([]*tournament.TransactionReply, numActvTxns)
			commitProofs := make([]*byzcoin.Proof, numActvTxns)
			var wg sync.WaitGroup
			wg.Add(numActvTxns)
			for i := 0; i < numActvTxns; i++ {
				go func(idx int) {
					defer wg.Done()
					cl := tournament.NewClient(byzcoin.NewClient(byzd.Cl.ID, byzd.Cl.Roster))
					origIdx := activeParticipants[idx]
					lotteryData[idx] = tournament.CreateLotteryData()
					cKey := fmt.Sprintf("commit_%d_%d", round, origIdx)
					ds := &tournament.DataStore{Data: lotteryData[idx].Commitment,
						Index: origIdx}
					commitReplies[idx], err = cl.AddTransaction(ds, cKey,
						writers[origIdx], wCtrs[origIdx], *wDarc, wait)
					if err != nil {
						log.Errorf("adding txn: %v", err)
					}
					wCtrs[origIdx]++
					commitProofs[idx], err = cl.WaitProof(commitReplies[idx].
						InstanceID, time.Duration(commons.WP_INTERVAL), nil)
					if err != nil {
						log.Error(err)
					}
					if !commitProofs[idx].InclusionProof.Match(commitReplies[idx].InstanceID.Slice()) {
						log.Errorf("commit inclusion proof does not match")
					}
				}(i)
			}
			wg.Wait()

			openReplies := make([]*tournament.TransactionReply, numActvTxns)
			openProofs := make([]*byzcoin.Proof, numActvTxns)
			m := monitor.NewTimeMeasure("open")
			for idx := 0; idx < numActvTxns; idx++ {
				origIdx := activeParticipants[idx]
				ds := &tournament.DataStore{Data: lotteryData[idx].Secret, Index: origIdx}
				oKey := fmt.Sprintf("open_%d_%d", round, origIdx)
				openReplies[idx], err = baseCl.AddTransaction(ds, oKey,
					writers[origIdx], wCtrs[origIdx], *wDarc, wait)
				if err != nil {
					log.Error(err)
				}
				wCtrs[origIdx]++
				openProofs[idx], err = baseCl.WaitProof(openReplies[idx].
					InstanceID, time.Duration(commons.WP_INTERVAL), nil)
				if err != nil {
					log.Error(err)
				}
				if !openProofs[idx].InclusionProof.Match(openReplies[idx].InstanceID.Slice()) {
					log.Errorf("open inclusion proof does not match")
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
		log.Info("Starting", s.ProtoName, s.NumTxns)
		s.Threshold = s.F + 1
		err = s.runOTSLottery(config)
	} else if s.ProtoName == "PQOTS" {
		log.Info("Starting", s.ProtoName, s.NumTxns)
		s.Threshold = s.F + 1
		s.VerifyThreshold = 2*s.F + 1
		err = s.runPQOTSLottery(config)
	} else if s.ProtoName == "Tournament" {
		log.Info("Starting", s.ProtoName, s.NumTxns)
		err = s.runTournamentLottery(config)
	} else {
		log.Fatal("invalid protocol name")
	}
	return err
}
