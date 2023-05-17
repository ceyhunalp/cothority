package pqots

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
	"time"
)

type Client struct {
	bcClient *byzcoin.Client
	c        *onet.Client
}

func NewClient(byzcoin *byzcoin.Client) *Client {
	return &Client{bcClient: byzcoin, c: onet.NewClient(
		cothority.Suite, ServiceName)}
}

// WriteReply is returned upon successfully spawning a Write instance.
type WriteReply struct {
	*byzcoin.AddTxResponse
	byzcoin.InstanceID
}

// ReadReply is is returned upon successfully spawning a Read instance.
type ReadReply struct {
	*byzcoin.AddTxResponse
	byzcoin.InstanceID
}

func (c *Client) VerifyWriteAll(t int, roster *onet.Roster, write *Write,
	shares []*share.PriShare, rands [][]byte) (*VerifyWriteReply, error) {
	reply := &VerifyWriteReply{}
	req := &VerifyWriteRequest{
		Roster:    roster,
		Threshold: t,
		Write:     write,
		Shares:    shares,
		Rands:     rands,
	}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], req, reply)
	return reply, err
}

func (c *Client) AddWrite(write *Write, sigs map[int][]byte, t int,
	signer darc.Signer, signerCtr uint64, darc darc.Darc,
	wait int) (reply *WriteReply, err error) {
	reply = &WriteReply{}
	txn := WriteTxn{
		Threshold: t,
		Write:     *write,
		Sigs:      sigs,
	}
	txnBuf, err := protobuf.Encode(&txn)
	if err != nil {
		return nil, xerrors.Errorf("encoding write request: %v", err)
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractPQOTSWriteID,
				Args: byzcoin.Arguments{{
					Name: "writetxn", Value: txnBuf}},
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

func (c *Client) AddRead(proof *byzcoin.Proof, signer darc.Signer,
	signerCtr uint64, wait int) (reply *ReadReply, err error) {
	var readBuf []byte
	read := &Read{
		Write: byzcoin.NewInstanceID(proof.InclusionProof.Key()),
		Xc:    signer.Ed25519.Point,
	}
	reply = &ReadReply{}
	readBuf, err = protobuf.Encode(read)
	if err != nil {
		return nil, xerrors.Errorf("encoding Read message: %v", err)
	}

	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(proof.InclusionProof.Key()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractPQOTSReadID,
				Args:       byzcoin.Arguments{{Name: "read", Value: readBuf}},
			},
			SignerCounter: []uint64{signerCtr},
		},
	)
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		return nil, xerrors.Errorf("signing txn: %v", err)
	}

	reply.InstanceID = ctx.Instructions[0].DeriveID("")
	reply.AddTxResponse, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, xerrors.Errorf("adding txn: %v", err)
	}
	return reply, nil
}

func (c *Client) DecryptKey(dkr *PQOTSDKRequest) (reply *PQOTSDKReply,
	err error) {
	reply = &PQOTSDKReply{}
	err = c.c.SendProtobuf(c.bcClient.Roster.List[0], dkr, reply)
	return reply, err
}

func (c *Client) BatchDecryptKey(dkr *PQOTSBatchDKRequest) (
	reply *PQOTSBatchDKReply, err error) {
	reply = &PQOTSBatchDKReply{}
	err = c.c.SendProtobuf(c.bcClient.Roster.List[0], dkr, reply)
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
