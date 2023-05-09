package protocol

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(NamePQOTS, NewPQOTS)
}

type PQOTS struct {
	*onet.TreeNodeInstance
	Xc        kyber.Point
	Share     *share.PriShare
	Threshold int
	Failures  int

	VerificationData []byte
	Verify           VerifyRequest

	Reencrypted   chan bool
	Reencryptions []*EGP
	replies       []PQOTSReencryptReply
	timeout       *time.Timer
	doneOnce      sync.Once
}

func NewPQOTS(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pqOts := &PQOTS{
		TreeNodeInstance: n,
		Reencrypted:      make(chan bool, 1),
	}
	err := pqOts.RegisterHandlers(pqOts.reencrypt, pqOts.reencryptReply)
	if err != nil {
		return nil, xerrors.Errorf("registering handlers: %v", err)
	}
	return pqOts, nil
}

func (p *PQOTS) Start() error {
	rc := &PQOTSReencrypt{
		Xc: p.Xc,
	}
	if len(p.VerificationData) > 0 {
		rc.VerificationData = &p.VerificationData
	}
	if p.Verify != nil {
		p.Share = p.Verify(rc)
		if p.Share == nil {
			p.finish(false)
			return xerrors.Errorf("refused to reencrypt")
		}
	}
	K, Cs, err := elGamalEncrypt(cothority.Suite, p.Xc, p.Share)
	if err != nil {
		p.finish(false)
		return xerrors.Errorf("cannot reencrypt:", err.Error())
	}
	p.replies = append(p.replies, PQOTSReencryptReply{
		Index: p.Share.I,
		Egp:   &EGP{K: K, Cs: Cs},
	})
	p.timeout = time.AfterFunc(10*time.Minute, func() {
		log.Lvl1("PQOTS protocol timeout")
		p.finish(false)
	})
	//errs := p.SendToChildrenInParallel(rc)
	errs := p.Broadcast(rc)
	if len(errs) > len(p.Roster().List)-p.Threshold {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *PQOTS) reencrypt(r structPQOTSReencrypt) error {
	log.Lvl3(p.Name() + ": starting reencrypt")
	defer p.Done()

	if p.Verify != nil {
		p.Share = p.Verify(&r.PQOTSReencrypt)
		if p.Share == nil {
			log.Lvl2(p.ServerIdentity(), "refused to reencrypt")
			return cothority.ErrorOrNil(p.SendToParent(&PQOTSReencryptReply{}),
				"sending PQOTSReencryptReply to parent")
		}
	}
	K, Cs, err := elGamalEncrypt(cothority.Suite, r.Xc, p.Share)
	if err != nil {
		log.Lvl2(p.ServerIdentity(), "cannot reencrypt")
		return cothority.ErrorOrNil(p.SendToParent(&PQOTSReencryptReply{}),
			"sending PQOTSReencryptReply to parent")
	}
	log.Lvl1(p.Name() + ": sending reply to parent")
	return cothority.ErrorOrNil(
		p.SendToParent(&PQOTSReencryptReply{
			Index: p.Share.I,
			Egp: &EGP{
				K:  K,
				Cs: Cs,
			},
		}), "sending PQOTSReencryptReply to parent",
	)
}

func (p *PQOTS) reencryptReply(rr structPQOTSReencryptReply) error {
	if rr.PQOTSReencryptReply.Egp == nil {
		log.Lvl2("Node", rr.ServerIdentity, "refused to reply")
		p.Failures++
		if p.Failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(rr.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	}
	p.replies = append(p.replies, rr.PQOTSReencryptReply)
	if len(p.replies) >= (p.Threshold) {
		p.Reencryptions = make([]*EGP, len(p.List()))
		for _, r := range p.replies {
			p.Reencryptions[r.Index] = r.Egp
		}
		p.finish(true)
	}
	return nil
}

func elGamalEncrypt(suite suites.Suite, pk kyber.Point,
	sh *share.PriShare) (kyber.Point, []kyber.Point, error) {
	shb, err := protobuf.Encode(sh)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot encode share: %v", err)
	}
	var Cs []kyber.Point
	k := suite.Scalar().Pick(suite.RandomStream())
	K := suite.Point().Mul(k, nil)
	S := suite.Point().Mul(k, pk)
	for len(shb) > 0 {
		kp := suite.Point().Embed(shb, suite.RandomStream())
		Cs = append(Cs, suite.Point().Add(S, kp))
		shb = shb[min(len(shb), kp.EmbedLen()):]
	}
	return K, Cs, nil

	//shp := suite.Point().Embed(shb, suite.RandomStream())
	//k := suite.Scalar().Pick(suite.RandomStream())
	//K := suite.Point().Mul(k, nil)
	//S := suite.Point().Mul(k, pk)
	//C := S.Add(S, shp)
	//return K, C, nil
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func (p *PQOTS) finish(result bool) {
	p.timeout.Stop()
	select {
	case p.Reencrypted <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	p.doneOnce.Do(func() { p.Done() })
}
