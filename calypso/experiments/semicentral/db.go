package semicentral

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
)

func NewSemiCentralDB(db *bolt.DB, bn []byte) *SemiCentralDB {
	return &SemiCentralDB{
		DB:         db,
		bucketName: bn,
	}
}

func (sdb *SemiCentralDB) StoreData(req *StoreRequest) (key string, err error) {
	dataHash := sha256.Sum256(req.Data)
	if bytes.Compare(dataHash[:], req.DataHash) != 0 {
		return key, xerrors.New("hashes do not match")
	}
	val, err := network.Marshal(req)
	if err != nil {
		return key, xerrors.Errorf("marshaling store request: %v", err)
	}
	err = sdb.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(sdb.bucketName)
		v := b.Get(dataHash[:])
		if v != nil {
			return xerrors.New("key already exists")
		}
		err := b.Put(dataHash[:], val)
		if err != nil {
			return xerrors.Errorf("storing value: %v", err)
		}
		return nil
	})
	if err != nil {
		log.Error(err)
		return key, xerrors.Errorf("updating db: %v", err)
	}
	return hex.EncodeToString(dataHash[:]), nil
}

func (sdb *SemiCentralDB) GetStoredData(key string) (*StoreRequest, error) {
	var result *StoreRequest
	keyByte, err := hex.DecodeString(key)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	err = sdb.DB.View(func(tx *bolt.Tx) error {
		v, err := sdb.getFromTx(tx, keyByte)
		if err != nil {
			return err
		}
		result = v
		return nil
	})
	if err != nil {
		log.Error(err)
	}
	return result, err
}

func (sdb *SemiCentralDB) getFromTx(tx *bolt.Tx, key []byte) (*StoreRequest, error) {
	val := tx.Bucket(sdb.bucketName).Get(key)
	if val == nil {
		return nil, xerrors.New("Key does not exist")
	}
	buf := make([]byte, len(val))
	copy(buf, val)
	_, sr, err := network.Unmarshal(buf, cothority.Suite)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return sr.(*StoreRequest), nil
}
