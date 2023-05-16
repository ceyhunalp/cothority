package protocol

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NameBatchPQOTS = "BatchPQOTS"

func init() {
	network.RegisterMessages(&PQOTSBatchRc{}, &PQOTSBatchRcReply{})
}

type VerifyBatchRequest func(input *BatchInput) *share.PriShare

type BatchInput struct {
	Xc               kyber.Point
	VerificationData []byte
}

type PQOTSBatchRc struct {
	BatchInput []*BatchInput
}

type structPQOTSBatchRc struct {
	*onet.TreeNode
	PQOTSBatchRc
}

type PQOTSBatchRcReply struct {
	Reply []*PQOTSReencryptReply
}

type structPQOTSBatchRcReply struct {
	*onet.TreeNode
	PQOTSBatchRcReply
}

type EGPairs struct {
	Pairs []*EGP
}
