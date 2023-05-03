package tournament

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
	"time"
)

type Client struct {
	bcClient *byzcoin.Client
}

func NewClient(byzcoin *byzcoin.Client) *Client {
	return &Client{bcClient: byzcoin}
}

type TransactionReply struct {
	*byzcoin.AddTxResponse
	byzcoin.InstanceID
}

type LotteryData struct {
	Secret     [32]byte
	Commitment [32]byte
}

type DataStore struct {
	Index int
	Data  [32]byte
}

func (c *Client) AddTransaction(ds *DataStore, key string,
	signer darc.Signer, signerCtr uint64, darc darc.Darc,
	wait int) (reply *TransactionReply, err error) {
	reply = &TransactionReply{}
	buf, err := protobuf.Encode(ds)
	if err != nil {
		return nil, xerrors.Errorf("encoding data store: %v", err)
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractTournamentID,
				Args: byzcoin.Arguments{{
					Name: key, Value: buf}},
			},
			SignerCounter: []uint64{signerCtr},
		},
	)
	//Sign the transaction
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		return nil, xerrors.Errorf("signing txn: %v", err)
	}
	reply.InstanceID = ctx.Instructions[0].DeriveID("")
	//Delegate the work to the byzcoin client
	reply.AddTxResponse, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, xerrors.Errorf("adding txn: %v", err)
	}
	return reply, err
}

func (c *Client) SpawnDarc(signer darc.Signer, signerCtr uint64,
	controlDarc darc.Darc, spawnDarc darc.Darc, wait int) (
	reply *byzcoin.AddTxResponse, err error) {
	darcBuf, err := spawnDarc.ToProto()
	if err != nil {
		return nil, xerrors.Errorf("serializing darc to protobuf: %v", err)
	}

	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(controlDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDarcID,
				Args: []byzcoin.Argument{{
					Name:  "darc",
					Value: darcBuf,
				}},
			},
			SignerCounter: []uint64{signerCtr},
		},
	)
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		return nil, xerrors.Errorf("signing txn: %v", err)
	}

	reply, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	return reply, cothority.ErrorOrNil(err, "adding txn")
}

// WaitProof calls the byzcoin client's wait proof
func (c *Client) WaitProof(id byzcoin.InstanceID, interval time.Duration,
	value []byte) (*byzcoin.Proof, error) {
	return c.bcClient.WaitProof(id, interval, value)
}
