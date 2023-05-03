package tournament

//import (
//	"bytes"
//	"crypto/sha256"
//	"fmt"
//	"github.com/BurntSushi/toml"
//	"go.dedis.ch/cothority/v3/byzcoin"
//	"go.dedis.ch/cothority/v3/calypso/experiments/commons"
//	"go.dedis.ch/onet/v3"
//	"go.dedis.ch/onet/v3/log"
//	"go.dedis.ch/protobuf"
//	"math"
//	"sort"
//	"time"
//)
//
//type SimulationService struct {
//	onet.SimulationBFTree
//	NumTxns   int
//	BlockTime int
//	NodeCount int
//}
//
//func init() {
//	onet.SimulationRegister("TournamentSim", NewTournamentSim)
//}
//
//func NewTournamentSim(config string) (onet.Simulation, error) {
//	ss := &SimulationService{}
//	_, err := toml.Decode(config, ss)
//	if err != nil {
//		return nil, err
//	}
//	return ss, nil
//}
//
//func (s *SimulationService) Setup(dir string,
//	hosts []string) (*onet.SimulationConfig, error) {
//	sc := &onet.SimulationConfig{}
//	s.CreateRoster(sc, hosts, 2000)
//	err := s.CreateTree(sc)
//	if err != nil {
//		return nil, err
//	}
//	return sc, nil
//}
//
//func (s *SimulationService) Node(config *onet.SimulationConfig) error {
//	index, _ := config.Roster.Search(config.Server.ServerIdentity.GetID())
//	if index < 0 {
//		log.Fatal("Didn't find this node in roster")
//	}
//	log.Lvl3("Initializing node-index", index)
//	return s.SimulationBFTree.Node(config)
//}
//
//func (s *SimulationService) runTournamentLottery(config *onet.SimulationConfig) error {
//	wait := 0
//	for r := 0; r < s.Rounds; r++ {
//		writers, wCtrs, wDarcs := CreateMultipleDarcs(s.NumTxns)
//
//		byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
//		if err != nil {
//			return err
//		}
//
//		cl := NewClient(byzd.Cl)
//		for i := 0; i < s.NumTxns; i++ {
//			_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarcs[i], 0)
//			if err != nil {
//				log.Error(err)
//				return err
//			}
//			byzd.AdminCtr++
//		}
//
//		lotteryRounds := int(math.Ceil(math.Log2(float64(s.NumTxns))))
//		numActvTxns := s.NumTxns
//		participants := make([]int, s.NumTxns)
//		for i := 0; i < s.NumTxns; i++ {
//			participants[i] = 1
//		}
//		isOdd := false
//		for round := 0; round < lotteryRounds; round++ {
//			activeParticipants := getActiveParticipants(participants)
//			if numActvTxns%2 != 0 {
//				numActvTxns -= 1
//				isOdd = true
//			}
//			lotteryData := make([]*LotteryData, numActvTxns)
//			commitReplies := make([]*TransactionReply, numActvTxns)
//			for i := 0; i < numActvTxns; i++ {
//				origIdx := activeParticipants[i]
//				lotteryData[i] = CreateLotteryData()
//				cKey := fmt.Sprintf("commit_%d_%d", round, origIdx)
//				ds := &DataStore{Data: lotteryData[i].Commitment,
//					Index: origIdx}
//				commitReplies[i], err = cl.AddTransaction(ds, cKey,
//					writers[origIdx], wCtrs[origIdx], *wDarcs[origIdx], wait)
//				//log.Infof("Commit for %d: %x", origIdx, ds.Data)
//				if err != nil {
//					log.Errorf("adding txn: %v", err)
//					return err
//				}
//				wCtrs[origIdx]++
//			}
//
//			commitProofs := make([]*byzcoin.Proof, numActvTxns)
//			for i := 0; i < numActvTxns; i++ {
//				commitProofs[i], err = cl.WaitProof(commitReplies[i].
//					InstanceID, time.Duration(s.BlockTime), nil)
//				if err != nil {
//					log.Error(err)
//					return err
//				}
//				if !commitProofs[i].InclusionProof.Match(commitReplies[i].InstanceID.Slice()) {
//					log.Errorf("commit inclusion proof does not match")
//					return err
//				}
//			}
//
//			openReplies := make([]*TransactionReply, numActvTxns)
//			for i := 0; i < numActvTxns; i++ {
//				origIdx := activeParticipants[i]
//				ds := &DataStore{Data: lotteryData[i].Secret, Index: origIdx}
//				oKey := fmt.Sprintf("open_%d_%d", round, origIdx)
//				openReplies[i], err = cl.AddTransaction(ds, oKey,
//					writers[origIdx], wCtrs[origIdx], *wDarcs[origIdx], wait)
//				if err != nil {
//					log.Error(err)
//					return err
//				}
//				//log.Infof("Open for %d: %x", origIdx, ds.Data)
//				wCtrs[origIdx]++
//			}
//
//			openProofs := make([]*byzcoin.Proof, numActvTxns)
//			for i := 0; i < numActvTxns; i++ {
//				openProofs[i], err = cl.WaitProof(openReplies[i].
//					InstanceID, time.Duration(s.BlockTime), nil)
//				if err != nil {
//					log.Error(err)
//					return err
//				}
//				if !openProofs[i].InclusionProof.Match(openReplies[i].InstanceID.Slice()) {
//					log.Errorf("open inclusion proof does not match")
//					return err
//				}
//			}
//
//			commits := make([]*DataStore, numActvTxns)
//			opens := make([]*DataStore, numActvTxns)
//			for i := 0; i < numActvTxns; i++ {
//				commits[i], err = recoverData(commitProofs[i])
//				if err != nil {
//					log.Error(err)
//					return err
//				}
//				opens[i], err = recoverData(openProofs[i])
//				if err != nil {
//					log.Error(err)
//					return err
//				}
//			}
//
//			sort.Slice(commits, func(i, j int) bool {
//				return commits[i].Index < commits[j].Index
//			})
//			sort.Slice(opens, func(i, j int) bool {
//				return opens[i].Index < opens[j].Index
//			})
//
//			var winnerList []int
//			for i := 0; i < numActvTxns; {
//				lSecret := opens[i].Data
//				rSecret := opens[i+1].Data
//				lHash := sha256.Sum256(lSecret[:])
//				rHash := sha256.Sum256(rSecret[:])
//				if bytes.Compare(lHash[:], commits[i].Data[:]) != 0 {
//					log.Lvl1("Digests do not match - winner is", i+1)
//					winnerList = append(winnerList, i+1)
//				} else {
//					if bytes.Compare(rHash[:], commits[i+1].Data[:]) != 0 {
//						log.Lvl1("Digests do not match - winner is", i)
//						winnerList = append(winnerList, i)
//					} else {
//						result := make([]byte, 32)
//						commons.SafeXORBytes(result, lSecret[:], rSecret[:])
//						lastDigit := int(result[31]) % 2
//						if lastDigit == 0 {
//							winnerList = append(winnerList, opens[i].Index)
//						} else {
//							winnerList = append(winnerList, opens[i+1].Index)
//						}
//					}
//				}
//				i += 2
//			}
//			if isOdd {
//				winnerList = append(winnerList, activeParticipants[numActvTxns])
//				numActvTxns += 1
//			}
//			numActvTxns = int(math.Ceil(float64(numActvTxns) / 2))
//			isOdd = false
//			organizeList(participants, winnerList)
//		}
//	}
//	return nil
//}
//
//func recoverData(pr *byzcoin.Proof) (*DataStore, error) {
//	_, val, _, _, err := pr.KeyValue()
//	if err != nil {
//		return nil, err
//	}
//	kvd := KeyValueData{}
//	err = protobuf.Decode(val, &kvd)
//	if err != nil {
//		return nil, err
//	}
//
//	ds := DataStore{}
//	err = protobuf.Decode(kvd.Storage[0].Value, &ds)
//	if err != nil {
//		return nil, err
//	}
//	return &ds, nil
//}
//
//func (s *SimulationService) Run(config *onet.SimulationConfig) error {
//	var err error
//	err = s.runTournamentLottery(config)
//	return err
//}
