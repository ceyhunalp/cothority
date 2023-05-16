package protocol

import (
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NameBatchOTS = "BatchOTS"

func init() {
	network.RegisterMessages(&OTSBatchReencrypt{},
		&OTSBatchReencryptReply{})
}

type VerifyBatchRequest func(input *BatchInput, idx int) (*pvss.PubVerShare,
	kyber.Point, darc.ID)

type BatchInput struct {
	Xc               kyber.Point
	VerificationData []byte
}

type OTSBatchReencrypt struct {
	BatchInput []*BatchInput
}

type structOTSBatchReencrypt struct {
	*onet.TreeNode
	OTSBatchReencrypt
}

type OTSBatchReencryptReply struct {
	Reply []*OTSReencryptReply
}

type structOTSBatchReencryptReply struct {
	*onet.TreeNode
	OTSBatchReencryptReply
}

type EGPairs struct {
	Pairs []*EGP
}
