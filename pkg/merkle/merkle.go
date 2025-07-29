// Package merkle provides Merkle tree functionality
package merkle

import (
	"crypto/sha256"
	"fmt"
)

// MerkleTree represents a Merkle tree
type MerkleTree struct {
	Root   *Node
	Leaves []*Node
}

// Node represents a node in the Merkle tree
type Node struct {
	Hash   []byte
	Left   *Node
	Right  *Node
	Parent *Node
	Data   []byte
}

// TreeBuilder builds Merkle trees
type TreeBuilder struct {
	hashFunc func([]byte) []byte
}

// Tree is an alias for MerkleTree for compatibility
type Tree = MerkleTree

// NewTreeBuilder creates a new TreeBuilder
func NewTreeBuilder() *TreeBuilder {
	return &TreeBuilder{
		hashFunc: func(data []byte) []byte {
			hash := sha256.Sum256(data)
			return hash[:]
		},
	}
}

// NewMerkleTree creates a new MerkleTree
func NewMerkleTree() *MerkleTree {
	return &MerkleTree{}
}

// Build builds a Merkle tree from the given data chunks
func (tb *TreeBuilder) Build(chunks [][]byte) (*MerkleTree, error) {
	if len(chunks) == 0 {
		return nil, fmt.Errorf("cannot build tree from empty chunks")
	}

	// Create leaf nodes
	var leaves []*Node
	for _, chunk := range chunks {
		node := &Node{
			Hash: tb.hashFunc(chunk),
			Data: chunk,
		}
		leaves = append(leaves, node)
	}

	// Build tree bottom-up
	currentLevel := leaves
	for len(currentLevel) > 1 {
		var nextLevel []*Node
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right *Node
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				// Duplicate the last node if odd number of nodes
				right = left
			}

			// Create parent node
			combinedHash := append(left.Hash, right.Hash...)
			parent := &Node{
				Hash:  tb.hashFunc(combinedHash),
				Left:  left,
				Right: right,
			}
			left.Parent = parent
			right.Parent = parent

			nextLevel = append(nextLevel, parent)
		}
		currentLevel = nextLevel
	}

	return &MerkleTree{
		Root:   currentLevel[0],
		Leaves: leaves,
	}, nil
}

// Verify verifies the integrity of a chunk using its Merkle proof
func (mt *MerkleTree) Verify(chunkIndex int, chunk []byte, proof [][]byte) bool {
	if chunkIndex >= len(mt.Leaves) {
		return false
	}

	// Calculate hash of the chunk
	hash := sha256.Sum256(chunk)
	currentHash := hash[:]

	// Verify proof path to root
	for _, proofHash := range proof {
		combined := append(currentHash, proofHash...)
		newHash := sha256.Sum256(combined)
		currentHash = newHash[:]
	}

	// Compare with root hash
	return string(currentHash) == string(mt.Root.Hash)
}

// GetProof generates a Merkle proof for a specific chunk
func (mt *MerkleTree) GetProof(chunkIndex int) [][]byte {
	if chunkIndex >= len(mt.Leaves) {
		return nil
	}

	var proof [][]byte
	current := mt.Leaves[chunkIndex]

	// Traverse up to root, collecting sibling hashes
	for current.Parent != nil {
		parent := current.Parent
		if parent.Left == current {
			// Current is left child, add right sibling
			proof = append(proof, parent.Right.Hash)
		} else {
			// Current is right child, add left sibling
			proof = append(proof, parent.Left.Hash)
		}
		current = parent
	}

	return proof
}

// AddLeaf adds a new leaf to the tree (simplified implementation)
func (mt *MerkleTree) AddLeaf(data []byte) error {
	hash := sha256.Sum256(data)
	node := &Node{
		Hash: hash[:],
		Data: data,
	}
	mt.Leaves = append(mt.Leaves, node)

	// Rebuild tree with new leaf
	var chunks [][]byte
	for _, leaf := range mt.Leaves {
		chunks = append(chunks, leaf.Data)
	}

	builder := NewTreeBuilder()
	newTree, err := builder.Build(chunks)
	if err != nil {
		return err
	}

	mt.Root = newTree.Root
	return nil
}

// GetRoot returns the root hash of the tree
func (mt *MerkleTree) GetRoot() []byte {
	if mt.Root == nil {
		return nil
	}
	return mt.Root.Hash
}
