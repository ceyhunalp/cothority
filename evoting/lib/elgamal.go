package lib

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/shuffle"
	"github.com/dedis/kyber/util/random"
)

// Encrypt performs the ElGamal encryption algorithm.
func Encrypt(public kyber.Point, message []byte) (K, C kyber.Point) {
	M := Suite.Point().Embed(message, random.New())

	// ElGamal-encrypt the point to produce ciphertext (K,C).
	k := Suite.Scalar().Pick(random.New()) // ephemeral private key
	K = Suite.Point().Mul(k, nil)          // ephemeral DH public key
	S := Suite.Point().Mul(k, public)      // ephemeral DH shared secret
	C = S.Add(S, M)                        // message blinded with secret
	return
}

// Decrypt performs the ElGamal decryption algorithm.
func Decrypt(private kyber.Scalar, K, C kyber.Point) kyber.Point {
	// ElGamal-decrypt the ciphertext (K,C) to reproduce the message.
	S := Suite.Point().Mul(private, K) // regenerate shared secret
	return Suite.Point().Sub(C, S)     // use to un-blind the message
}

// Verify performs verifies the proof of a Neff shuffle.
func Verify(tag []byte, public kyber.Point, x, y, v, w []kyber.Point) error {
	verifier := shuffle.Verifier(Suite, nil, public, x, y, v, w)
	return proof.HashVerify(Suite, "", verifier, tag)
}
