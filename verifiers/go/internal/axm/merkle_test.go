package axm

import (
	"encoding/hex"
	"path/filepath"
	"sort"
	"testing"
)

type merkleVectors struct {
	EmptyRoot string `json:"empty_root"`
	Leaves    []struct {
		Relpath      string `json:"relpath"`
		ContentUTF8  string `json:"content_utf8"`
		ExpectedLeaf string `json:"expected_leaf"`
	} `json:"leaves"`
	Nodes []struct {
		Left         string `json:"left"`
		Right        string `json:"right"`
		ExpectedNode string `json:"expected_node"`
	} `json:"nodes"`
	Trees []struct {
		Name         string            `json:"name"`
		Files        map[string]string `json:"files"`
		ExpectedRoot string            `json:"expected_root"`
	} `json:"trees"`
}

func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func TestMerkleVectors(t *testing.T) {
	var vec merkleVectors
	loadJSON(t, filepath.Join(vectorsDir(t), "merkle.json"), &vec)
	if len(vec.Leaves) == 0 || len(vec.Trees) == 0 {
		t.Fatal("merkle vectors empty — wrong path?")
	}

	if got := hex.EncodeToString(func() []byte { r := MerkleRoot(nil); return r[:] }()); got != vec.EmptyRoot {
		t.Errorf("empty root: got %s, want %s", got, vec.EmptyRoot)
	}
	if EmptyMerkleRoot != vec.EmptyRoot {
		t.Errorf("EmptyMerkleRoot constant %s != vector %s", EmptyMerkleRoot, vec.EmptyRoot)
	}

	for i, l := range vec.Leaves {
		leaf := MerkleLeaf(l.Relpath, []byte(l.ContentUTF8))
		if got := hex.EncodeToString(leaf[:]); got != l.ExpectedLeaf {
			t.Errorf("leaves[%d] (%s): got %s, want %s", i, l.Relpath, got, l.ExpectedLeaf)
		}
	}

	for i, n := range vec.Nodes {
		node := MerkleNode(hex32(t, n.Left), hex32(t, n.Right))
		if got := hex.EncodeToString(node[:]); got != n.ExpectedNode {
			t.Errorf("nodes[%d]: got %s, want %s", i, got, n.ExpectedNode)
		}
	}

	for _, tree := range vec.Trees {
		relpaths := make([]string, 0, len(tree.Files))
		for p := range tree.Files {
			relpaths = append(relpaths, p)
		}
		sort.Strings(relpaths) // bytewise UTF-8 order per spec 8.1
		leaves := make([][32]byte, 0, len(relpaths))
		for _, p := range relpaths {
			leaves = append(leaves, MerkleLeaf(p, []byte(tree.Files[p])))
		}
		root := MerkleRoot(leaves)
		if got := hex.EncodeToString(root[:]); got != tree.ExpectedRoot {
			t.Errorf("trees[%s]: got %s, want %s", tree.Name, got, tree.ExpectedRoot)
		}
	}
}
