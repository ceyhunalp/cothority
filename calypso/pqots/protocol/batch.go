package protocol

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(NameBatchPQOTS, NewBatchPQOTS)
}

type BatchPQOTS struct {
	*onet.TreeNodeInstance
	Share     *share.PriShare
	Threshold int
	Failures  int

	BatchInput []*BatchInput

	VerificationData []byte
	Verify           VerifyBatchRequest

	Reencrypted   chan bool
	Reencryptions []*EGPairs
	replies       []PQOTSBatchRcReply
	timeout       *time.Timer
	doneOnce      sync.Once
}

func NewBatchPQOTS(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	batchPqOts := &BatchPQOTS{
		TreeNodeInstance: n,
		Reencrypted:      make(chan bool, 1),
	}
	err := batchPqOts.RegisterHandlers(batchPqOts.batchReencrypt,
		batchPqOts.batchReencryptReply)
	if err != nil {
		return nil, xerrors.Errorf("registering handlers: %v", err)
	}
	return batchPqOts, nil
}

func (p *BatchPQOTS) Start() error {
	if p.BatchInput == nil || len(p.BatchInput) == 0 {
		return xerrors.New("missing input")
	}
	if p.Verify == nil {
		return xerrors.New("missing verification function")
	}
	sz := len(p.BatchInput)
	p.Reencryptions = make([]*EGPairs, sz)
	for i := 0; i < sz; i++ {
		p.Reencryptions[i] = &EGPairs{Pairs: make([]*EGP, len(p.List()))}
	}
	for idx, in := range p.BatchInput {
		p.Share = p.Verify(in)
		if p.Share == nil {
			p.finish(false)
			return xerrors.Errorf("refused to reencrypt")
		}
		K, Cs, err := elGamalEncrypt(cothority.Suite, in.Xc, p.Share)
		if err != nil {
			p.finish(false)
			return xerrors.Errorf("cannot reencrypt:", err.Error())
		}
		p.Reencryptions[idx].Pairs[p.Share.I] = &EGP{K: K, Cs: Cs}
	}
	p.timeout = time.AfterFunc(10*time.Minute, func() {
		log.Lvl1("PQOTS protocol timeout")
		p.finish(false)
	})
	//errs := p.SendToChildrenInParallel(rc)
	errs := p.Broadcast(&PQOTSBatchRc{BatchInput: p.BatchInput})
	if len(errs) > len(p.Roster().List)-p.Threshold {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *BatchPQOTS) batchReencrypt(r structPQOTSBatchRc) error {
	log.Lvl3(p.Name() + ": starting reencrypt")
	defer p.Done()

	if p.Verify == nil {
		return cothority.ErrorOrNil(p.SendToParent(&PQOTSBatchRcReply{}),
			"sending PQOTSBatchRcReply to parent")
	}
	p.BatchInput = r.BatchInput
	reply := make([]*PQOTSReencryptReply, len(p.BatchInput))
	for idx, in := range p.BatchInput {
		p.Share = p.Verify(in)
		if p.Share == nil {
			log.Lvl2(p.ServerIdentity(), "refused to reencrypt")
			return cothority.ErrorOrNil(p.SendToParent(&PQOTSBatchRcReply{}),
				"sending PQOTSBatchRcReply to parent")
		}
		K, Cs, err := elGamalEncrypt(cothority.Suite, in.Xc, p.Share)
		if err != nil {
			log.Lvl2(p.ServerIdentity(), "cannot reencrypt")
			return cothority.ErrorOrNil(p.SendToParent(&PQOTSBatchRcReply{}),
				"sending PQOTSBatchRcReply to parent")
		}
		reply[idx] = &PQOTSReencryptReply{
			Index: p.Share.I,
			Egp:   &EGP{K: K, Cs: Cs},
		}
	}
	log.Lvl1(p.Name() + ": sending reply to parent")
	return cothority.ErrorOrNil(
		p.SendToParent(&PQOTSBatchRcReply{Reply: reply}),
		"sending PQOTSBatchRcReply to parent",
	)
}

func (p *BatchPQOTS) batchReencryptReply(rr structPQOTSBatchRcReply) error {
	if rr.Reply == nil || len(rr.Reply) == 0 {
		log.Lvl2("Node", rr.ServerIdentity, "refused to reply")
		p.Failures++
		if p.Failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(rr.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	}
	p.replies = append(p.replies, rr.PQOTSBatchRcReply)
	if len(p.replies) >= (p.Threshold - 1) {
		for _, br := range p.replies {
			for idx, r := range br.Reply {
				p.Reencryptions[idx].Pairs[r.Index] = r.Egp
			}
		}
		p.finish(true)
	}
	return nil
}

func (p *BatchPQOTS) finish(result bool) {
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
