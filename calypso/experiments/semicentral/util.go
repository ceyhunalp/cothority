package semicentral

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"io"
)

const nonceLen = 12

func NewSCWrite(data []byte, reader kyber.Point,
	serverKey kyber.Point) (*SCWrite, []byte, error) {
	var symKey [16]byte
	random.Bytes(symKey[:], random.New())
	encData, err := symEncrypt(data, symKey[:])
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	k, c, _ := ElGamalEncrypt(serverKey, symKey[:])
	dh := sha256.Sum256(encData)

	readerBytes, err := reader.MarshalBinary()
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	encReader, err := symEncrypt(readerBytes, symKey[:])
	if err != nil {
		log.Error(err)
		return nil, nil, err
	}
	w := &SCWrite{
		DataHash:  dh[:],
		K:         k,
		C:         c,
		Reader:    reader,
		EncReader: encReader,
	}
	return w, encData, nil
}

func RecoverData(encData []byte, sk kyber.Scalar, k kyber.Point, c kyber.Point) ([]byte, error) {
	recvKey, err := ElGamalDecrypt(sk, k, c)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return AeadOpen(recvKey, encData)
}

func symEncrypt(msg []byte, key []byte) ([]byte, error) {
	encData, err := aeadSeal(key[:], msg)
	if err != nil {
		log.Error(err)
	}
	return encData, err
}

func aeadSeal(symKey, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(symKey)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, nonceLen)
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	encData := aesgcm.Seal(nil, nonce, data, nil)
	encData = append(encData, nonce...)
	return encData, nil
}

func AeadOpen(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	if len(ciphertext) < 12 {
		log.Errorf("ciphertext too short")
		return nil, xerrors.New("ciphertext too short")
	}
	nonce := ciphertext[len(ciphertext)-nonceLen:]
	out, err := aesgcm.Open(nil, nonce, ciphertext[0:len(ciphertext)-nonceLen], nil)
	return out, err
}

func ElGamalEncrypt(pk kyber.Point, msg []byte) (K, C kyber.Point, remainder []byte) {
	// Embed the message (or as much of it as will fit) into a curve point.
	M := cothority.Suite.Point().Embed(msg, random.New())
	max := cothority.Suite.Point().EmbedLen()
	if max > len(msg) {
		max = len(msg)
	}
	remainder = msg[max:]
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := cothority.Suite.Scalar().Pick(random.New()) // ephemeral private key
	K = cothority.Suite.Point().Mul(k, nil)          // ephemeral DH public key
	S := cothority.Suite.Point().Mul(k, pk)          // ephemeral DH shared secret
	C = S.Add(S, M)                                  // message blinded with secret
	return
}

func ElGamalDecrypt(sk kyber.Scalar, K kyber.Point, C kyber.Point) ([]byte, error) {
	S := cothority.Suite.Point().Mul(sk, K)
	M := cothority.Suite.Point().Sub(C, S)
	return M.Data()
}

func CompareKeys(readerPt kyber.Point, decReader []byte) (int, error) {
	readerPtBytes, err := readerPt.MarshalBinary()
	if err != nil {
		log.Errorf("CompareKeys error: %v", err)
		return -1, err
	}
	same := bytes.Compare(readerPtBytes, decReader)
	return same, nil
}
