package axm

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"lukechampine.com/blake3"
)

// EmptyMerkleRoot is BLAKE3(0x01), the frozen empty-tree constant
// (spec 8.2). It is defined for completeness; a valid shard always has at
// least one covered file.
const EmptyMerkleRoot = "48fc721fbbc172e0925fa27af1671de225ba927134802998b10a1568a188652b"

// MerkleLeaf computes leaf = BLAKE3(0x00 || relpath_utf8 || 0x00 || file_bytes).
func MerkleLeaf(relpath string, content []byte) [32]byte {
	h := blake3.New(32, nil)
	h.Write([]byte{0x00})
	h.Write([]byte(relpath))
	h.Write([]byte{0x00})
	h.Write(content)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// merkleLeafFile streams a file into the leaf hash.
func merkleLeafFile(relpath, fsPath string) ([32]byte, error) {
	var out [32]byte
	f, err := os.Open(fsPath)
	if err != nil {
		return out, err
	}
	defer f.Close()
	h := blake3.New(32, nil)
	h.Write([]byte{0x00})
	h.Write([]byte(relpath))
	h.Write([]byte{0x00})
	if _, err := io.Copy(h, f); err != nil {
		return out, err
	}
	copy(out[:], h.Sum(nil))
	return out, nil
}

// MerkleNode computes node = BLAKE3(0x01 || left || right).
func MerkleNode(left, right [32]byte) [32]byte {
	h := blake3.New(32, nil)
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// MerkleRoot reduces the ordered leaves to the root: adjacent pairs are
// combined left-to-right; an odd last node is promoted unchanged to the
// next level (RFC 6962 style — never duplicated). One leaf is its own
// root; zero leaves yield the frozen empty-root constant.
func MerkleRoot(leaves [][32]byte) [32]byte {
	if len(leaves) == 0 {
		h := blake3.New(32, nil)
		h.Write([]byte{0x01})
		var out [32]byte
		copy(out[:], h.Sum(nil))
		return out
	}
	level := leaves
	for len(level) > 1 {
		next := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, MerkleNode(level[i], level[i+1]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
	}
	return level[0]
}

// merkleRootOfShard computes the root over the covered files of a shard:
// every regular file except manifest.json and everything under sig/
// (spec 8.1). relpaths MUST already be sorted by UTF-8 bytes ascending.
func merkleRootOfShard(shardDir string, sortedRelpaths []string) ([32]byte, error) {
	leaves := make([][32]byte, 0, len(sortedRelpaths))
	for _, rel := range sortedRelpaths {
		leaf, err := merkleLeafFile(rel, filepath.Join(shardDir, filepath.FromSlash(rel)))
		if err != nil {
			return [32]byte{}, fmt.Errorf("hashing %s: %w", rel, err)
		}
		leaves = append(leaves, leaf)
	}
	return MerkleRoot(leaves), nil
}
