package semicentral

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
	"sync"
)

const ServiceName = "SemiCentralizedService"

func init() {
	var err error
	_, err = onet.RegisterNewService(ServiceName, newSemiCentralizedService)
	log.ErrFatal(err)
	err = byzcoin.RegisterGlobalContract(ContractSCWriteID,
		contractSCWriteFromBytes)
	if err != nil {
		log.ErrFatal(err)
	}
	err = byzcoin.RegisterGlobalContract(ContractSCReadID,
		contractSCReadFromBytes)
	if err != nil {
		log.ErrFatal(err)
	}
	network.RegisterMessages(&storage{})
}

// Service is our template-service
type Service struct {
	*onet.ServiceProcessor
	db                *SemiCentralDB
	storage           *storage
	genesisBlocks     map[string]*skipchain.SkipBlock
	genesisBlocksLock sync.Mutex
	storedKeys        map[string][]byte
	skLock            sync.Mutex
}

// storageID reflects the data we're storing - we could store more
// than one structure.
var storageID = []byte("SemiCentral")

// storage is used to save our data.
type storage struct {
	sync.Mutex
}

//func (s *Service) StoreData(req *StoreRequest) (*StoreReply, error) {
//	storedKey, err := s.db.StoreData(req)
//	if err != nil {
//		return nil, err
//	}
//	reply := &StoreReply{
//		StoredKey: storedKey,
//	}
//	return reply, nil
//}

func (s *Service) StoreData(req *StoreRequest) (*StoreReply, error) {
	dataHash := sha256.Sum256(req.Data)
	if bytes.Compare(dataHash[:], req.DataHash) != 0 {
		return nil, xerrors.New("hashes do not match")
	}
	val, err := protobuf.Encode(req)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	keyStr := hex.EncodeToString(dataHash[:])
	s.skLock.Lock()
	s.storedKeys[keyStr] = val
	s.skLock.Unlock()
	reply := &StoreReply{
		StoredKey: keyStr,
	}
	return reply, nil
}

func (s *Service) Decrypt(req *SCDecryptRequest) (*SCDecryptReply, error) {
	sk := s.ServerIdentity().GetPrivate()
	//storedData, err := s.db.GetStoredData(req.Key)
	var storedData StoreRequest
	val := s.storedKeys[req.Key]
	err := protobuf.Decode(val, &storedData)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	writeTxn, err := s.verifyDecryptRequest(req, &storedData)
	//writeTxn, err := s.verifyDecryptRequest(req, storedData)
	if err != nil {
		log.Errorf("getDecryptedData error: %v", err)
		return nil, err
	}
	k, c, err := reencryptData(writeTxn, sk)
	if err != nil {
		log.Errorf("getDecryptedData error: %v", err)
		return nil, err
	}
	return &SCDecryptReply{Data: storedData.Data, DataHash: storedData.DataHash, K: k, C: c}, nil
}

func reencryptData(wt *SCWrite, sk kyber.Scalar) (kyber.Point, kyber.Point, error) {
	symKey, err := ElGamalDecrypt(sk, wt.K, wt.C)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	decReader, err := AeadOpen(symKey, wt.EncReader)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	ok, err := CompareKeys(wt.Reader, decReader)
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	if ok != 0 {
		log.Error(err)
		return nil, nil, xerrors.New("Reader public key does not match")
	}
	k, c, _ := ElGamalEncrypt(wt.Reader, symKey)
	return k, c, nil
}

func (s *Service) verifyDecryptRequest(req *SCDecryptRequest,
	storedData *StoreRequest) (*SCWrite, error) {
	log.Lvl2("Re-encrypt the key to the public key of the reader")

	err := s.verifyProof(&req.Read)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	err = s.verifyProof(&req.Write)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	var read calypso.Read
	if err := req.Read.VerifyAndDecode(cothority.Suite, ContractSCReadID, &read); err != nil {
		return nil, xerrors.New("didn't get a read instance: " + err.Error())
	}
	var write SCWrite
	if err := req.Write.VerifyAndDecode(cothority.Suite,
		ContractSCWriteID, &write); err != nil {
		return nil, xerrors.New("didn't get a write instance: " + err.Error())
	}
	if !read.Write.Equal(byzcoin.NewInstanceID(req.Write.InclusionProof.Key())) {
		return nil, xerrors.New("read doesn't point to passed write")
	}

	keyBytes, err := hex.DecodeString(req.Key)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	ok := bytes.Compare(keyBytes, storedData.DataHash)
	if ok != 0 {
		log.Error("keys do not match")
		return nil, xerrors.New("keys do not match")
	}
	err = schnorr.Verify(cothority.Suite, write.Reader, keyBytes, req.Sig)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &write, nil
}

func (s *Service) verifyProof(proof *byzcoin.Proof) error {
	scID := proof.Latest.SkipChainID()
	sb, err := s.fetchGenesisBlock(scID, proof.Latest.Roster)
	if err != nil {
		return xerrors.Errorf("fetching genesis block: %v", err)
	}

	return cothority.ErrorOrNil(proof.VerifyFromBlock(sb),
		"verifying proof from block")
}
func (s *Service) fetchGenesisBlock(scID skipchain.SkipBlockID, roster *onet.Roster) (*skipchain.SkipBlock, error) {
	s.genesisBlocksLock.Lock()
	defer s.genesisBlocksLock.Unlock()
	sb := s.genesisBlocks[string(scID)]
	if sb != nil {
		return sb, nil
	}

	cl := skipchain.NewClient()
	sb, err := cl.GetSingleBlock(roster, scID)
	if err != nil {
		return nil, xerrors.Errorf("getting single block: %v", err)
	}

	// Genesis block can be reused later on.
	s.genesisBlocks[string(scID)] = sb

	return sb, nil
}

// saves all data.
func (s *Service) save() {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageID, s.storage)
	if err != nil {
		log.Error("Couldn't save data:", err)
	}
}

// Tries to load the configuration and updates the data in the service
// if it finds a valid config-file.
func (s *Service) tryLoad() error {
	s.storage = &storage{}
	msg, err := s.Load(storageID)
	if err != nil {
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.storage, ok = msg.(*storage)
	if !ok {
		return xerrors.New("Data of wrong type")
	}
	return nil
}

// newService receives the context that holds information about the node it's
// running on. Saving and loading can be done using the context. The data will
// be stored in memory for tests and simulations, and on disk for real deployments.
func newSemiCentralizedService(c *onet.Context) (onet.Service, error) {
	db, bucket := c.GetAdditionalBucket([]byte("sc_txns"))
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		db:               NewSemiCentralDB(db, bucket),
		genesisBlocks:    make(map[string]*skipchain.SkipBlock),
		storedKeys:       make(map[string][]byte),
	}
	if err := s.RegisterHandlers(s.StoreData, s.Decrypt); err != nil {
		return nil, xerrors.New("Couldn't register messages")
	}
	if err := s.tryLoad(); err != nil {
		log.Error(err)
		return nil, err
	}
	return s, nil
}
