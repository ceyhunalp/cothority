package commons

import (
	"fmt"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso/ots"
	"go.dedis.ch/cothority/v3/calypso/pqots"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"time"
)

type ByzData struct {
	Roster   *onet.Roster
	Cl       *byzcoin.Client
	Admin    darc.Signer
	AdminCtr uint64
	GMsg     *byzcoin.CreateGenesisBlock
	GDarc    *darc.Darc
	Csr      *byzcoin.CreateGenesisBlockResponse
}

func SetupByzcoin(r *onet.Roster, blockTime int) (*ByzData, error) {
	var err error
	byzd := &ByzData{}
	byzd.Admin = darc.NewSignerEd25519(nil, nil)
	byzd.AdminCtr = uint64(1)
	byzd.GMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, r,
		nil, byzd.Admin.Identity())
	if err != nil {
		log.Errorf("setting up byzcoin: %v", err)
		return nil, err
	}
	byzd.GMsg.BlockInterval = time.Duration(blockTime) * time.Second
	byzd.GDarc = &byzd.GMsg.GenesisDarc
	byzd.Cl, _, err = byzcoin.NewLedger(byzd.GMsg, false)
	if err != nil {
		log.Errorf("setting up byzcoin: %v", err)
		return nil, err
	}
	return byzd, nil
}

func CreateDarcs(pname string) (darc.Signer, darc.Signer, *darc.Darc) {
	writer := darc.NewSignerEd25519(nil, nil)
	reader := darc.NewSignerEd25519(nil, nil)
	writeDarc := darc.NewDarc(darc.InitRules([]darc.Identity{writer.Identity()},
		[]darc.Identity{writer.Identity()}), []byte("Writer"))
	if pname == "OTS" {
		writeDarc.Rules.AddRule("spawn:"+ots.ContractOTSWriteID,
			expression.InitOrExpr(writer.Identity().String()))
		writeDarc.Rules.AddRule("spawn:"+ots.ContractOTSReadID,
			expression.InitOrExpr(reader.Identity().String()))
	} else {
		writeDarc.Rules.AddRule("spawn:"+pqots.ContractPQOTSWriteID,
			expression.InitOrExpr(writer.Identity().String()))
		writeDarc.Rules.AddRule("spawn:"+pqots.ContractPQOTSReadID,
			expression.InitOrExpr(reader.Identity().String()))
	}
	return writer, reader, writeDarc
}

//func CreateMultipleDarcs(pname string, count int) ([]darc.Signer, []uint64, darc.Signer, []*darc.Darc) {
//	writers := make([]darc.Signer, count)
//	ctrs := make([]uint64, count)
//	writeDarcs := make([]*darc.Darc, count)
//	reader := darc.NewSignerEd25519(nil, nil)
//	for i := 0; i < count; i++ {
//		writers[i] = darc.NewSignerEd25519(nil, nil)
//		ctrs[i] = 1
//	}
//	for i := 0; i < count; i++ {
//		writeDarcs[i] = darc.NewDarc(darc.InitRules([]darc.Identity{writers[i].
//			Identity()}, []darc.Identity{writers[i].Identity()}),
//			[]byte(fmt.Sprint("writer_%d", i)))
//		if pname == "OTS" {
//			writeDarcs[i].Rules.AddRule("spawn:"+ots.ContractOTSWriteID,
//				expression.InitOrExpr(writers[i].Identity().String()))
//			writeDarcs[i].Rules.AddRule("spawn:"+ots.ContractOTSReadID,
//				expression.InitOrExpr(reader.Identity().String()))
//		} else {
//			writeDarcs[i].Rules.AddRule("spawn:"+pqots.ContractPQOTSWriteID,
//				expression.InitOrExpr(writers[i].Identity().String()))
//			writeDarcs[i].Rules.AddRule("spawn:"+pqots.ContractPQOTSReadID,
//				expression.InitOrExpr(reader.Identity().String()))
//		}
//	}
//	return writers, ctrs, reader, writeDarcs
//}

func CreateMultipleDarcs(pname string, count int) ([]darc.Signer, []uint64, []darc.Signer, []uint64, []*darc.Darc) {
	writers := make([]darc.Signer, count)
	wCtrs := make([]uint64, count)
	readers := make([]darc.Signer, count)
	rCtrs := make([]uint64, count)
	writeDarcs := make([]*darc.Darc, count)
	for i := 0; i < count; i++ {
		writers[i] = darc.NewSignerEd25519(nil, nil)
		wCtrs[i] = 1
		readers[i] = darc.NewSignerEd25519(nil, nil)
		rCtrs[i] = 1
	}
	for i := 0; i < count; i++ {
		writeDarcs[i] = darc.NewDarc(darc.InitRules([]darc.Identity{writers[i].
			Identity()}, []darc.Identity{writers[i].Identity()}),
			[]byte(fmt.Sprintf("writer_%d", i)))
		if pname == "OTS" {
			writeDarcs[i].Rules.AddRule("spawn:"+ots.ContractOTSWriteID,
				expression.InitOrExpr(writers[i].Identity().String()))
			writeDarcs[i].Rules.AddRule("spawn:"+ots.ContractOTSReadID,
				expression.InitOrExpr(readers[i].Identity().String()))
		} else {
			writeDarcs[i].Rules.AddRule("spawn:"+pqots.ContractPQOTSWriteID,
				expression.InitOrExpr(writers[i].Identity().String()))
			writeDarcs[i].Rules.AddRule("spawn:"+pqots.ContractPQOTSReadID,
				expression.InitOrExpr(readers[i].Identity().String()))
		}
	}
	return writers, wCtrs, readers, rCtrs, writeDarcs
}

func SafeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
