package protocol

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NamePQOTS = "PQOTS"

func init() {
	network.RegisterMessages(&PQOTSReencrypt{}, &PQOTSReencryptReply{})
}

type VerifyRequest func(rc *PQOTSReencrypt) *share.PriShare

type PQOTSReencrypt struct {
	Xc               kyber.Point
	VerificationData *[]byte
}

type structPQOTSReencrypt struct {
	*onet.TreeNode
	PQOTSReencrypt
}

type PQOTSReencryptReply struct {
	Index int
	Egp   *EGP
}

type structPQOTSReencryptReply struct {
	*onet.TreeNode
	PQOTSReencryptReply
}

type EGP struct {
	K  kyber.Point
	Cs []kyber.Point
}
