package protocol

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(NameBatchOTS, NewBatchOTS)
}

type BatchOTS struct {
	*onet.TreeNodeInstance
	Threshold int
	Failures  int

	BatchInput []*BatchInput

	Share    *pvss.PubVerShare
	Proof    kyber.Point
	PolicyID darc.ID

	Verify VerifyBatchRequest

	Reencrypted   chan bool
	Reencryptions []*EGPairs
	replies       []OTSBatchReencryptReply
	timeout       *time.Timer
	doneOnce      sync.Once
}

func NewBatchOTS(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	o := &BatchOTS{
		TreeNodeInstance: n,
		Reencrypted:      make(chan bool, 1),
	}
	err := o.RegisterHandlers(o.batchReencrypt, o.batchReencryptReply)
	if err != nil {
		return nil, xerrors.Errorf("registering handlers: %v", err)
	}
	return o, nil
}

func (o *BatchOTS) Start() error {
	if o.BatchInput == nil || len(o.BatchInput) == 0 {
		log.Errorf("missing input")
		return xerrors.New("missing input")
	}
	if o.Verify == nil {
		log.Errorf("missing verification function")
		return xerrors.New("missing verification function")
	}
	sz := len(o.BatchInput)
	o.Reencryptions = make([]*EGPairs, sz)
	for i := 0; i < sz; i++ {
		o.Reencryptions[i] = &EGPairs{Pairs: make([]*EGP, len(o.List()))}
	}
	for idx, in := range o.BatchInput {
		o.Share, o.Proof, o.PolicyID = o.Verify(in, o.Index())
		if o.Share == nil || o.Proof == nil || o.PolicyID == nil {
			log.Errorf("refused to reencrypt")
			o.finish(false)
			return xerrors.Errorf("refused to reencrypt")
		}
		h := createPointH(o.PolicyID)
		sh, err := pvss.DecShare(cothority.Suite, h, o.Public(), o.Proof,
			o.Private(), o.Share)
		if err != nil {
			log.Error(err)
			o.finish(false)
			return xerrors.Errorf("cannot reencrypt:", err.Error())
		}
		K, Cs, err := elGamalEncrypt(cothority.Suite, in.Xc, sh)
		if err != nil {
			log.Error(err)
			o.finish(false)
			return xerrors.Errorf("cannot reencrypt:", err.Error())
		}
		o.Reencryptions[idx].Pairs[sh.S.I] = &EGP{K: K, Cs: Cs}
	}

	o.timeout = time.AfterFunc(10*time.Minute, func() {
		log.Lvl1("OTS protocol timeout")
		o.finish(false)
	})
	//errs := o.SendToChildrenInParallel(rc)
	errs := o.Broadcast(&OTSBatchReencrypt{BatchInput: o.BatchInput})
	if len(errs) > len(o.Roster().List)-o.Threshold {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (o *BatchOTS) batchReencrypt(r structOTSBatchReencrypt) error {
	log.Lvl3(o.Name() + ": starting reencrypt")
	defer o.Done()
	if o.Verify == nil {
		log.Errorf("missing verification function")
		return cothority.ErrorOrNil(o.SendToParent(&OTSBatchReencryptReply{}),
			"sending OTSBatchReencryptReply to parent")
	}
	o.BatchInput = r.BatchInput
	reply := make([]*OTSReencryptReply, len(o.BatchInput))
	for idx, in := range o.BatchInput {
		o.Share, o.Proof, o.PolicyID = o.Verify(in, o.Index())
		if o.Share == nil || o.Proof == nil || o.PolicyID == nil {
			log.Errorf("refused to renecyrpt")
			return cothority.ErrorOrNil(o.SendToParent(&OTSReencryptReply{}),
				"sending OTSBatchReencryptReply to parent")
		}
		h := createPointH(o.PolicyID)
		sh, err := pvss.DecShare(cothority.Suite, h, o.Public(), o.Proof,
			o.Private(), o.Share)
		if err != nil {
			log.Error(err)
			return cothority.ErrorOrNil(o.SendToParent(&OTSReencryptReply{}),
				"sending OTSBatchReencryptReply to parent")
		}
		K, Cs, err := elGamalEncrypt(cothority.Suite, in.Xc, sh)
		if err != nil {
			log.Error(err)
			return cothority.ErrorOrNil(o.SendToParent(&OTSReencryptReply{}),
				"sending OTSBatchReencryptReply to parent")
		}
		reply[idx] = &OTSReencryptReply{
			Index: sh.S.I,
			Egp:   &EGP{K: K, Cs: Cs},
		}
	}
	return cothority.ErrorOrNil(o.SendToParent(&OTSBatchReencryptReply{Reply: reply}), "sending OTSBatchReencryptReply to parent")
}

func (o *BatchOTS) batchReencryptReply(rr structOTSBatchReencryptReply) error {
	if rr.Reply == nil || len(rr.Reply) == 0 {
		log.Lvl2("Node", rr.ServerIdentity, "refused to reply")
		o.Failures++
		if o.Failures > len(o.Roster().List)-o.Threshold {
			log.Lvl2(rr.ServerIdentity, "couldn't get enough shares")
			o.finish(false)
		}
		return nil
	}
	o.replies = append(o.replies, rr.OTSBatchReencryptReply)
	if len(o.replies) >= o.Threshold-1 {
		for _, br := range o.replies {
			for idx, r := range br.Reply {
				o.Reencryptions[idx].Pairs[r.Index] = r.Egp
			}
		}
		o.finish(true)
	}
	return nil
}

func (o *BatchOTS) finish(result bool) {
	o.timeout.Stop()
	select {
	case o.Reencrypted <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	o.doneOnce.Do(func() { o.Done() })
}
