package protocol

import (
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NamePQOTSVerify = "PQOTSVerify"

func init() {
	network.RegisterMessages(&PQOTSVerify{}, &PQOTSVerifyReply{})
}

type ExecuteFn func(int, []byte) (*share.PriShare, []byte, error)

type PQOTSVerify struct {
	VfData []byte
}

type structPQOTSVerify struct {
	*onet.TreeNode
	PQOTSVerify
}

type PQOTSVerifyReply struct {
	Index int
	Sig   []byte
}

type structPQOTSVerifyReply struct {
	*onet.TreeNode
	PQOTSVerifyReply
}
