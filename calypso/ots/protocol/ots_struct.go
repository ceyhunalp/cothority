package protocol

import (
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const NameOTS = "OTS"

func init() {
	network.RegisterMessages(&OTSReencrypt{}, &OTSReencryptReply{})
}

type VerifyRequest func(rc *OTSReencrypt, idx int) (*pvss.PubVerShare, kyber.Point, darc.ID)

type OTSReencrypt struct {
	Xc               kyber.Point
	VerificationData *[]byte
}

type structOTSReencrypt struct {
	*onet.TreeNode
	OTSReencrypt
}

type OTSReencryptReply struct {
	Index int
	Egp   *EGP
}

type structOTSReencryptReply struct {
	*onet.TreeNode
	OTSReencryptReply
}

type EGP struct {
	K  kyber.Point
	Cs []kyber.Point
}
