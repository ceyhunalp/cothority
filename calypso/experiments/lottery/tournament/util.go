package tournament

import (
	"crypto/sha256"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/protobuf"
)

//func CreateMultipleDarcs(count int) ([]darc.Signer, []uint64, []*darc.Darc) {
//	writers := make([]darc.Signer, count)
//	wCtrs := make([]uint64, count)
//	writeDarcs := make([]*darc.Darc, count)
//	for i := 0; i < count; i++ {
//		writers[i] = darc.NewSignerEd25519(nil, nil)
//		wCtrs[i] = 1
//	}
//	for i := 0; i < count; i++ {
//		writeDarcs[i] = darc.NewDarc(darc.InitRules([]darc.Identity{writers[i].
//			Identity()}, []darc.Identity{writers[i].Identity()}),
//			[]byte(fmt.Sprintf("writer_%d", i)))
//		writeDarcs[i].Rules.AddRule("spawn:"+ContractTournamentID,
//			expression.InitOrExpr(writers[i].Identity().String()))
//	}
//	return writers, wCtrs, writeDarcs
//}

func CreateMultiClientDarc(count int) ([]darc.Signer, []uint64, *darc.Darc) {
	writers := make([]darc.Signer, count)
	wCtrs := make([]uint64, count)

	ids := make([]darc.Identity, count)
	wrIdStrs := make([]string, count)

	for i := 0; i < count; i++ {
		writers[i] = darc.NewSignerEd25519(nil, nil)
		wCtrs[i] = 1
		ids[i] = writers[i].Identity()
		wrIdStrs[i] = writers[i].Identity().String()
	}

	wd := darc.NewDarc(darc.InitRules(ids, ids), []byte("writers"))
	wd.Rules.AddRule("spawn:"+ContractTournamentID,
		expression.InitOrExpr(wrIdStrs...))
	return writers, wCtrs, wd
	//for i := 0; i < count; i++ {
	//	writeDarcs[i] = darc.NewDarc(darc.InitRules([]darc.Identity{writers[i].
	//		Identity()}, []darc.Identity{writers[i].Identity()}),
	//		[]byte(fmt.Sprintf("writer_%d", i)))
	//	writeDarcs[i].Rules.AddRule("spawn:"+ContractTournamentID,
	//		expression.InitOrExpr(writers[i].Identity().String()))
	//}
	//return writers, wCtrs, writeDarcs
}

func CreateLotteryData() *LotteryData {
	var secret [32]byte
	random.Bytes(secret[:], random.New())
	commitment := sha256.Sum256(secret[:])
	ld := &LotteryData{
		Secret:     secret,
		Commitment: commitment,
	}
	return ld
}

func GetActiveParticipants(ps []int) []int {
	var activeParticipants []int
	for i, p := range ps {
		if p == 1 {
			activeParticipants = append(activeParticipants, i)
		}
	}
	return activeParticipants
}

func OrganizeList(pList []int, wList []int) {
	pIdx := 0
	wIdx := 0
	for pIdx < len(pList) && wIdx < len(wList) {
		if pIdx != wList[wIdx] {
			pList[pIdx] = 0
		} else {
			wIdx++
		}
		pIdx++
	}
	for pIdx < len(pList) {
		pList[pIdx] = 0
		pIdx++
	}
}

func RecoverData(pr *byzcoin.Proof) (*DataStore, error) {
	_, val, _, _, err := pr.KeyValue()
	if err != nil {
		return nil, err
	}
	kvd := KeyValueData{}
	err = protobuf.Decode(val, &kvd)
	if err != nil {
		return nil, err
	}

	ds := DataStore{}
	err = protobuf.Decode(kvd.Storage[0].Value, &ds)
	if err != nil {
		return nil, err
	}
	return &ds, nil
}
