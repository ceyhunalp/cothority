package trie

import (
	"bytes"
	"crypto/sha256"
	"errors"

	bolt "github.com/coreos/bbolt"
)

// Proof TODO the proof structure
type Proof struct {
	Interiors []interiorNode // the final one should be root
	Leaf      leafNode
	Empty     emptyNode
	Value     []byte
	Nonce     []byte
}

func (p *Proof) addInterior(node interiorNode) {
	p.Interiors = append(p.Interiors, node)
}

// Exists checks the proof for inclusion/absence
func (p *Proof) Exists(key []byte) (bool, error) {
	bits := toBinarySlice(key)
	expectedHash := p.Interiors[0].hash()
	var i int
	for i = range p.Interiors {
		if !bytes.Equal(p.Interiors[i].hash(), expectedHash) {
			return false, errors.New("invalid hash chain")
		}
		if bits[i] {
			expectedHash = p.Interiors[i].Left
		} else {
			expectedHash = p.Interiors[i].Right
		}
	}
	if bytes.Equal(expectedHash, p.Leaf.hash(p.Nonce)) {
		if equal(bits[:i], p.Empty.Prefix) {
			return false, errors.New("invalid prefix in leaf node")
		}
		if !bytes.Equal(p.Leaf.Key, key) {
			return false, nil
		}
		valHash := sha256.Sum256(p.Value)
		if !bytes.Equal(p.Leaf.DataKey, valHash[:]) {
			return false, errors.New("invalid value hash")
		}
		return true, nil
	} else if bytes.Equal(expectedHash, p.Empty.hash(p.Nonce)) {
		if equal(bits[:i], p.Empty.Prefix) {
			return false, errors.New("invalid prefix in empty node")
		}
		return false, nil
	} else {
		return false, errors.New("invalid edge node")
	}
}

func equal(a []bool, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GetProof TODO
func (t *Trie) GetProof(key []byte) (*Proof, error) {
	p := &Proof{}
	err := t.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(t.bucket)
		if b == nil {
			return errors.New("no such bucket")
		}
		rootKey := t.getRoot(b)
		if rootKey == nil {
			return errors.New("no root key")
		}
		p.Nonce = make([]byte, len(t.nonce))
		copy(p.Nonce, t.nonce)
		return t.getProof(0, rootKey, toBinarySlice(key), p, b)
	})
	return p, err
}

// getProof updates Proof p as it traverses the tree.
func (t *Trie) getProof(depth int, nodeKey []byte, bits []bool, p *Proof, b *bolt.Bucket) error {
	nodeVal := b.Get(nodeKey)
	if len(nodeVal) == 0 {
		return errors.New("invalid node key")
	}
	switch nodeType(nodeVal[0]) {
	case typeEmpty:
		node, err := decodeEmptyNode(nodeVal)
		if err != nil {
			return err
		}
		p.Empty = node
		return nil
	case typeLeaf:
		node, err := decodeLeafNode(nodeVal)
		if err != nil {
			return err
		}
		p.Leaf = node
		val := b.Get(node.DataKey)
		p.Value = make([]byte, len(val))
		copy(p.Value, val)
		return nil
	case typeInterior:
		node, err := decodeInteriorNode(nodeVal)
		if err != nil {
			return err
		}
		p.addInterior(node)
		if bits[depth] {
			return t.getProof(depth+1, node.Left, bits, p, b)
		}
		// look right
		return t.getProof(depth+1, node.Right, bits, p, b)
	}
	return errors.New("invalid node type")
}
