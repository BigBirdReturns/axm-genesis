package axm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorsDir points at tests/vectors/ in the repository root
// (verifiers/go/internal/axm -> four levels up).
func vectorsDir(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "..", "..", "tests", "vectors"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func loadJSON(t *testing.T, path string, into any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read vector file %s: %v", path, err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		t.Fatalf("cannot parse vector file %s: %v", path, err)
	}
}

type identityVectors struct {
	Canonicalization []struct {
		Input         string `json:"input"`
		Expected      string `json:"expected"`
		ExpectedError string `json:"expected_error"`
		Comment       string `json:"comment"`
	} `json:"canonicalization"`
	EntityIDs []struct {
		Namespace  string `json:"namespace"`
		Label      string `json:"label"`
		ExpectedID string `json:"expected_id"`
	} `json:"entity_ids"`
	ClaimIDs []struct {
		Subject    string `json:"subject"`
		Predicate  string `json:"predicate"`
		Object     string `json:"object"`
		ObjectType string `json:"object_type"`
		ExpectedID string `json:"expected_id"`
	} `json:"claim_ids"`
	ProvenanceIDs []struct {
		ClaimID    string `json:"claim_id"`
		SourceHash string `json:"source_hash"`
		ByteStart  int64  `json:"byte_start"`
		ByteEnd    int64  `json:"byte_end"`
		ExpectedID string `json:"expected_id"`
	} `json:"provenance_ids"`
	SpanIDs []struct {
		SourceHash string `json:"source_hash"`
		ByteStart  int64  `json:"byte_start"`
		ByteEnd    int64  `json:"byte_end"`
		Text       string `json:"text"`
		ExpectedID string `json:"expected_id"`
	} `json:"span_ids"`
}

func TestIdentityVectors(t *testing.T) {
	var vec identityVectors
	loadJSON(t, filepath.Join(vectorsDir(t), "identity.json"), &vec)
	if len(vec.Canonicalization) == 0 || len(vec.EntityIDs) == 0 || len(vec.ClaimIDs) == 0 {
		t.Fatal("identity vectors empty — wrong path?")
	}

	for i, c := range vec.Canonicalization {
		got, err := Canonicalize(c.Input)
		if c.ExpectedError != "" {
			if err == nil {
				t.Errorf("canonicalization[%d] (%s): want error %s, got %q", i, c.Comment, c.ExpectedError, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("canonicalization[%d] (%s): unexpected error %v", i, c.Comment, err)
			continue
		}
		if got != c.Expected {
			t.Errorf("canonicalization[%d] (%s): input %q: got %q, want %q", i, c.Comment, c.Input, got, c.Expected)
		}
	}

	for i, c := range vec.EntityIDs {
		got, err := EntityID(c.Namespace, c.Label)
		if err != nil {
			t.Errorf("entity_ids[%d]: %v", i, err)
			continue
		}
		if got != c.ExpectedID {
			t.Errorf("entity_ids[%d] (%s / %q): got %s, want %s", i, c.Namespace, c.Label, got, c.ExpectedID)
		}
	}

	for i, c := range vec.ClaimIDs {
		got, err := ClaimID(c.Subject, c.Predicate, c.ObjectType, c.Object)
		if err != nil {
			t.Errorf("claim_ids[%d]: %v", i, err)
			continue
		}
		if got != c.ExpectedID {
			t.Errorf("claim_ids[%d]: got %s, want %s", i, got, c.ExpectedID)
		}
	}

	for i, c := range vec.ProvenanceIDs {
		if got := ProvenanceID(c.ClaimID, c.SourceHash, c.ByteStart, c.ByteEnd); got != c.ExpectedID {
			t.Errorf("provenance_ids[%d]: got %s, want %s", i, got, c.ExpectedID)
		}
	}

	for i, c := range vec.SpanIDs {
		if got := SpanID(c.SourceHash, c.ByteStart, c.ByteEnd, c.Text); got != c.ExpectedID {
			t.Errorf("span_ids[%d]: got %s, want %s", i, got, c.ExpectedID)
		}
	}
}
