package semicentral

import (
	"encoding/hex"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
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

func (c *Client) StoreData(data []byte, dataHash []byte) (*StoreReply, error) {
	sr := &StoreRequest{
		Data:     data,
		DataHash: dataHash,
	}
	reply := &StoreReply{}
	err := c.c.SendProtobuf(c.bcClient.Roster.List[0], sr, reply)
	if err != nil {
		log.Errorf("Storing encrypted data failed: %v", err)
		return nil, err
	}
	return reply, nil
}

func (c *Client) AddWrite(write *SCWrite, signer darc.Signer,
	signerCtr uint64, darc darc.Darc, wait int) (reply *WriteReply, err error) {
	reply = &WriteReply{}
	wb, err := protobuf.Encode(write)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractSCWriteID,
				Args: byzcoin.Arguments{{
					Name: "write", Value: wb}},
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
	reply.AddTxResponse, err = c.bcClient.AddTransactionAndWait(ctx, wait)
	if err != nil {
		return nil, xerrors.Errorf("adding txn: %v", err)
	}
	return reply, err
}

func (c *Client) AddRead(proof *byzcoin.Proof, signer darc.Signer,
	signerCtr uint64, wait int) (reply *ReadReply, err error) {
	reply = &ReadReply{}
	read := &calypso.Read{
		Write: byzcoin.NewInstanceID(proof.InclusionProof.Key()),
		Xc:    signer.Ed25519.Point,
	}
	rb, err := protobuf.Encode(read)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion,
		byzcoin.Instruction{
			InstanceID: byzcoin.NewInstanceID(proof.InclusionProof.Key()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractSCReadID,
				Args:       byzcoin.Arguments{{Name: "read", Value: rb}},
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

func (c *Client) Decrypt(dr *DecryptRequest, sk kyber.Scalar) (*DecryptReply, error) {
	keyBytes, err := hex.DecodeString(dr.Key)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	sig, err := schnorr.Sign(cothority.Suite, sk, keyBytes)
	if err != nil {
		log.Errorf("Decrypt failed: %v", err)
		return nil, err
	}
	dr.Sig = sig
	reply := &DecryptReply{}
	err = c.c.SendProtobuf(c.bcClient.Roster.List[0], dr, reply)
	if err != nil {
		log.Error(err)
		return nil, err
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
