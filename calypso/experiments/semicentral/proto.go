package semicentral

import (
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3/network"
	bolt "go.etcd.io/bbolt"
)

func init() {
	network.RegisterMessages(&StoreRequest{}, &StoreReply{},
		&DecryptRequest{}, &DecryptReply{})
}

type SemiCentralDB struct {
	*bolt.DB
	bucketName []byte
}

type SCWrite struct {
	DataHash  []byte
	K         kyber.Point
	C         kyber.Point
	Reader    kyber.Point
	EncReader []byte
}

type StoreRequest struct {
	Data     []byte
	DataHash []byte
}

type StoreReply struct {
	StoredKey string
}

type DecryptRequest struct {
	Write byzcoin.Proof
	Read  byzcoin.Proof
	Key   string
	Sig   []byte
}

type DecryptReply struct {
	Data     []byte
	DataHash []byte
	K        kyber.Point
	C        kyber.Point
}
