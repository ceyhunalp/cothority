package commons

import (
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
	//byzd.GMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, r,
	//	[]string{"spawn:" + calypso.ContractLongTermSecretID},
	//	byzd.Admin.Identity())
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

func CreateDarcs() (darc.Signer, darc.Signer, *darc.Darc) {
	writer := darc.NewSignerEd25519(nil, nil)
	reader := darc.NewSignerEd25519(nil, nil)
	writeDarc := darc.NewDarc(darc.InitRules([]darc.Identity{writer.Identity()},
		[]darc.Identity{writer.Identity()}), []byte("Writer"))
	writeDarc.Rules.AddRule("spawn:"+ots.ContractOTSWriteID,
		expression.InitOrExpr(writer.Identity().String()))
	writeDarc.Rules.AddRule("spawn:"+ots.ContractOTSReadID,
		expression.InitOrExpr(reader.Identity().String()))
	writeDarc.Rules.AddRule("spawn:"+pqots.ContractPQOTSWriteID,
		expression.InitOrExpr(writer.Identity().String()))
	writeDarc.Rules.AddRule("spawn:"+pqots.ContractPQOTSReadID,
		expression.InitOrExpr(reader.Identity().String()))
	//writeDarc.Rules.AddRule(darc.Action("spawn:"+calypso.ContractWriteID),
	//	expression.InitOrExpr(writer.Identity().String()))
	//writeDarc.Rules.AddRule(darc.Action("spawn:"+calypso.ContractReadID),
	//	expression.InitOrExpr(reader.Identity().String()))
	return writer, reader, writeDarc
}
