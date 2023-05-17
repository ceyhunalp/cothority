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
	onet.GlobalProtocolRegister(NamePQOTSVerify, NewPQOTSVf)
}

type PQOTSVf struct {
	*onet.TreeNodeInstance
	VfData    [][]byte
	ExecFn    ExecuteFn
	Share     *share.PriShare
	Sig       []byte
	Threshold int
	Failures  int

	Sigs     map[int][]byte
	Verified chan bool
	replies  []PQOTSVerifyReply
	timeout  *time.Timer
	doneOnce sync.Once
}

func NewPQOTSVf(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pqVf := &PQOTSVf{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
		Sigs:             make(map[int][]byte),
	}
	err := pqVf.RegisterHandlers(pqVf.verify, pqVf.verifyReply)
	if err != nil {
		return nil, xerrors.Errorf("registering handlers: %v", err)
	}
	return pqVf, nil
}

func (p *PQOTSVf) Start() error {
	var err error
	if len(p.VfData) == 0 {
		p.finish(false)
		return xerrors.New("missing vf data")
	}
	if p.ExecFn == nil {
		p.finish(false)
		return xerrors.New("missing function")
	}
	idx := p.Index()
	p.Share, p.Sig, err = p.ExecFn(idx, p.VfData[idx])
	if err != nil {
		log.Error(err)
		p.finish(false)
		return err
	}
	p.replies = append(p.replies, PQOTSVerifyReply{
		Index: idx,
		Sig:   p.Sig,
	})
	p.timeout = time.AfterFunc(10*time.Minute, func() {
		log.Lvl1("PQOTS verify protocol timeout")
		p.finish(false)
	})
	var errs []error
	for i, node := range p.List() {
		if !node.Equal(p.TreeNode()) {
			if err := p.SendTo(node, &PQOTSVerify{VfData: p.VfData[i]}); err != nil {
				errs = append(errs, xerrors.Errorf("sending: %v", err))
			}
		}
	}
	if len(errs) > len(p.Roster().List)-p.Threshold {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *PQOTSVf) verify(v structPQOTSVerify) error {
	defer p.Done()
	log.Lvl1(p.ServerIdentity().String(), "received request")
	var err error
	idx := p.Index()
	p.Share, p.Sig, err = p.ExecFn(idx, v.VfData)
	if err != nil {
		log.Error(err)
		return cothority.ErrorOrNil(p.SendToParent(&PQOTSVerifyReply{}),
			"sending PQOTSVerifyReply to parent")
	}
	return cothority.ErrorOrNil(p.SendToParent(&PQOTSVerifyReply{Index: idx, Sig: p.Sig}),
		"sending PQOTSVerifyReply to parent",
	)
}

func (p *PQOTSVf) verifyReply(vv structPQOTSVerifyReply) error {
	if len(vv.Sig) == 0 {
		log.Lvl2("Node", vv.ServerIdentity, "refused to reply")
		p.Failures++
		if p.Failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(vv.ServerIdentity, "couldn't get enough replies")
			p.finish(false)
		}
		return nil
	}
	p.replies = append(p.replies, vv.PQOTSVerifyReply)
	if len(p.replies) >= (p.Threshold) {
		for _, r := range p.replies {
			p.Sigs[r.Index] = r.Sig
		}
		p.finish(true)
	}
	return nil
}

func (p *PQOTSVf) finish(result bool) {
	p.timeout.Stop()
	select {
	case p.Verified <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	p.doneOnce.Do(func() { p.Done() })
}
