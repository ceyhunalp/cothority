package main

import (
	"go.dedis.ch/cothority/v3/calypso/pqots"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3/simul/monitor"
	"math/rand"
	"time"

	"github.com/BurntSushi/toml"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/calypso/experiments/commons"
	"go.dedis.ch/cothority/v3/calypso/ots"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share/pvss"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

type SimulationService struct {
	onet.SimulationBFTree
	NodeCount       int
	F               int
	Threshold       int
	VerifyThreshold int
	BlockTime       int
	ProtoName       string
	Publics         []kyber.Point
}

func init() {
	onet.SimulationRegister("ProtocolSim", NewProtocolSim)
}

func NewProtocolSim(config string) (onet.Simulation, error) {
	ss := &SimulationService{}
	_, err := toml.Decode(config, ss)
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (s *SimulationService) Setup(dir string,
	hosts []string) (*onet.SimulationConfig, error) {
	sc := &onet.SimulationConfig{}
	s.CreateRoster(sc, hosts, 2000)
	err := s.CreateTree(sc)
	if err != nil {
		return nil, err
	}
	return sc, nil
}

func (s *SimulationService) Node(config *onet.SimulationConfig) error {
	index, _ := config.Roster.Search(config.Server.ServerIdentity.GetID())
	if index < 0 {
		log.Fatal("Didn't find this node in roster")
	}
	log.Lvl3("Initializing node-index", index)
	return s.SimulationBFTree.Node(config)
}

func (s *SimulationService) runOTS(config *onet.SimulationConfig) error {
	// Setup
	writer, reader, wDarc := commons.CreateDarcs(s.ProtoName)
	byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
	if err != nil {
		return err
	}
	cl := ots.NewClient(byzd.Cl)
	_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarc, 2)
	if err != nil {
		log.Error(err)
		return err
	}
	byzd.AdminCtr++

	wait := 0
	writerCtr := uint64(1)
	readerCtr := uint64(1)
	for i := 0; i < s.Rounds; i++ {
		cwr := monitor.NewTimeMeasure("cl_wr")
		shares, _, pr, secret, err := ots.RunPVSS(cothority.Suite,
			s.NodeCount, s.Threshold, s.Publics, wDarc.GetID())
		if err != nil {
			log.Error(err)
			return err
		}
		mesg := make([]byte, 128)
		rand.Read(mesg)
		ctxt, ctxtHash, err := ots.Encrypt(cothority.Suite, secret, mesg)
		if err != nil {
			log.Error(err)
			return err
		}
		w := ots.Write{
			PolicyID: wDarc.GetID(),
			Shares:   shares,
			Proofs:   pr,
			Publics:  s.Publics,
			CtxtHash: ctxtHash,
		}
		cwr.Record()

		acw := monitor.NewTimeMeasure("ac_wr")
		wrReply, err := cl.AddWrite(&w, writer, writerCtr, *wDarc, wait)
		if err != nil {
			log.Error(err)
			return err
		}
		wrPr, err := cl.WaitProof(wrReply.InstanceID, time.Duration(commons.WP_INTERVAL), nil)
		if err != nil {
			log.Error(err)
			return err
		}
		acw.Record()

		acr := monitor.NewTimeMeasure("ac_r")
		rReply, err := cl.AddRead(wrPr, reader, readerCtr, wait)
		if err != nil {
			log.Error(err)
			return err
		}
		rPr, err := cl.WaitProof(rReply.InstanceID, time.Duration(commons.WP_INTERVAL), nil)
		if err != nil {
			log.Error(err)
			return err
		}
		acr.Record()

		_, err = cl.DecryptKey(&ots.OTSDKRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Read:      *rPr,
			Write:     *wrPr,
		})
		if err != nil {
			log.Error(err)
			return err
		}

		smd := monitor.NewTimeMeasure("decrypt")
		dkr, err := cl.DecryptKey(&ots.OTSDKRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Read:      *rPr,
			Write:     *wrPr,
		})
		if err != nil {
			log.Error(err)
			return err
		}
		smd.Record()

		r := monitor.NewTimeMeasure("recover")
		var keys []kyber.Point
		var encShares []*pvss.PubVerShare
		g := cothority.Suite.Point().Base()
		decShares := ots.ElGamalDecrypt(cothority.Suite, reader.Ed25519.Secret,
			dkr.Reencryptions)
		for _, ds := range decShares {
			keys = append(keys, s.Publics[ds.S.I])
			encShares = append(encShares, shares[ds.S.I])
		}
		recSecret, err := pvss.RecoverSecret(cothority.Suite, g, keys, encShares,
			decShares, s.Threshold, s.NodeCount)
		if err != nil {
			log.Error(err)
			return err
		}
		_, err = ots.Decrypt(recSecret, ctxt)
		if err != nil {
			log.Error(err)
			return err
		}
		r.Record()
		writerCtr++
		readerCtr++
	}
	return nil
}

func (s *SimulationService) runPQOTS(config *onet.SimulationConfig) error {
	writer, reader, wDarc := commons.CreateDarcs(s.ProtoName)
	byzd, err := commons.SetupByzcoin(config.Roster, s.BlockTime)
	if err != nil {
		return err
	}
	cl := pqots.NewClient(byzd.Cl)
	_, err = cl.SpawnDarc(byzd.Admin, byzd.AdminCtr, *byzd.GDarc, *wDarc, 2)
	if err != nil {
		log.Error(err)
		return err
	}
	byzd.AdminCtr++

	wait := 0
	writerCtr := uint64(1)
	readerCtr := uint64(1)
	for i := 0; i < s.Rounds; i++ {
		cwr := monitor.NewTimeMeasure("cl_wr")
		poly := pqots.GenerateSSPoly(s.Threshold)
		shares, rands, commitments, err := pqots.GenerateCommitments(poly,
			s.NodeCount)
		if err != nil {
			log.Error(err)
			return err
		}
		mesg := make([]byte, 128)
		rand.Read(mesg)
		ctxt, ctxtHash, err := pqots.Encrypt(poly.Secret(), mesg)
		if err != nil {
			log.Error(err)
			return err
		}
		wr := pqots.Write{Commitments: commitments, Publics: s.Publics,
			CtxtHash: ctxtHash}
		cwr.Record()

		v := monitor.NewTimeMeasure("verify_wr")
		reply, err := cl.VerifyWriteAll(s.VerifyThreshold, config.Roster, &wr,
			shares, rands)
		if err != nil {
			return err
		}
		v.Record()
		acw := monitor.NewTimeMeasure("ac_wr")
		wReply, err := cl.AddWrite(&wr, reply.Sigs, s.VerifyThreshold, writer,
			writerCtr, *wDarc, wait)
		if err != nil {
			log.Error(err)
			return err
		}
		wrPr, err := cl.WaitProof(wReply.InstanceID,
			time.Duration(commons.WP_INTERVAL), nil)
		if err != nil {
			log.Error(err)
			return err
		}
		acw.Record()

		acr := monitor.NewTimeMeasure("ac_r")
		rReply, err := cl.AddRead(wrPr, reader, readerCtr, wait)
		if err != nil {
			log.Error(err)
			return err
		}
		rPr, err := cl.WaitProof(rReply.InstanceID,
			time.Duration(commons.WP_INTERVAL), nil)
		if err != nil {
			log.Error(err)
			return err
		}
		acr.Record()

		_, err = cl.DecryptKey(&pqots.PQOTSDKRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Read:      *rPr,
			Write:     *wrPr,
		})
		if err != nil {
			log.Error(err)
			return err
		}
		dm := monitor.NewTimeMeasure("decrypt")
		dkr, err := cl.DecryptKey(&pqots.PQOTSDKRequest{
			Roster:    config.Roster,
			Threshold: s.Threshold,
			Read:      *rPr,
			Write:     *wrPr,
		})
		if err != nil {
			log.Error(err)
			return err
		}
		dm.Record()

		r := monitor.NewTimeMeasure("recover")
		decShares := pqots.ElGamalDecrypt(cothority.Suite, reader.Ed25519.Secret, dkr.Reencryptions)
		recSecret, err := share.RecoverSecret(cothority.Suite, decShares,
			s.Threshold, s.NodeCount)
		if err != nil {
			log.Error(err)
			return err
		}
		_, err = pqots.Decrypt(recSecret, ctxt)
		if err != nil {
			log.Error(err)
			return err
		}
		r.Record()
		writerCtr++
		readerCtr++
	}
	return nil
}

func (s *SimulationService) Run(config *onet.SimulationConfig) error {
	var err error
	s.NodeCount = len(config.Roster.List)
	s.Publics = config.Roster.Publics()
	if s.ProtoName == "OTS" {
		log.Info("OTS")
		s.Threshold = s.F + 1
		err = s.runOTS(config)
	} else {
		log.Info("PQOTS")
		s.Threshold = s.F + 1
		s.VerifyThreshold = 2*s.F + 1
		err = s.runPQOTS(config)
	}
	return err
}
