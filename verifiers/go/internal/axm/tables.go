package axm

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"unicode/utf8"
)

type fieldKind int

const (
	fieldString fieldKind = iota
	fieldInt
)

type tableSchema struct {
	rel        string // e.g. "graph/entities.jsonl"
	primaryKey string
	fields     map[string]fieldKind
}

var (
	entityIDRe = regexp.MustCompile(`^e1_[a-z2-7]{52}$`)
	claimIDRe  = regexp.MustCompile(`^c1_[a-z2-7]{52}$`)
	provIDRe   = regexp.MustCompile(`^p1_[a-z2-7]{52}$`)
	spanIDRe   = regexp.MustCompile(`^s1_[a-z2-7]{52}$`)
)

var idSyntaxRe = map[string]*regexp.Regexp{
	"entity_id":     entityIDRe,
	"claim_id":      claimIDRe,
	"provenance_id": provIDRe,
	"span_id":       spanIDRe,
}

var validObjectTypes = map[string]bool{
	"entity": true, "literal:string": true, "literal:integer": true,
	"literal:decimal": true, "literal:boolean": true,
}

var coreSchemas = []tableSchema{
	{
		rel: "graph/entities.jsonl", primaryKey: "entity_id",
		fields: map[string]fieldKind{
			"entity_id": fieldString, "namespace": fieldString,
			"label": fieldString, "entity_type": fieldString,
		},
	},
	{
		rel: "graph/claims.jsonl", primaryKey: "claim_id",
		fields: map[string]fieldKind{
			"claim_id": fieldString, "subject": fieldString,
			"predicate": fieldString, "object": fieldString,
			"object_type": fieldString, "tier": fieldInt,
		},
	},
	{
		rel: "graph/provenance.jsonl", primaryKey: "provenance_id",
		fields: map[string]fieldKind{
			"provenance_id": fieldString, "claim_id": fieldString,
			"source_hash": fieldString, "byte_start": fieldInt, "byte_end": fieldInt,
		},
	},
	{
		rel: "evidence/spans.jsonl", primaryKey: "span_id",
		fields: map[string]fieldKind{
			"span_id": fieldString, "source_hash": fieldString,
			"byte_start": fieldInt, "byte_end": fieldInt, "text": fieldString,
		},
	},
}

// Stage 6 — core tables (spec section 11): canonical JSONL form, exact key
// sets, types, enums, bytewise row order, primary-key uniqueness.
func (v *verifier) checkTables() {
	for _, schema := range coreSchemas {
		rows := v.parseTable(schema)
		switch schema.rel {
		case "graph/entities.jsonl":
			v.entities = rows
		case "graph/claims.jsonl":
			v.claims = rows
		case "graph/provenance.jsonl":
			v.provenance = rows
		case "evidence/spans.jsonl":
			v.spans = rows
		}
	}
}

// parseTable validates one core table file and returns its parsed rows.
// It stops at the first error in the file (verification stops at the end
// of the stage anyway).
func (v *verifier) parseTable(schema tableSchema) []map[string]any {
	data, err := os.ReadFile(v.shardFile(schema.rel))
	if err != nil {
		v.addf("E_SCHEMA_READ", "%s: unreadable: %v", schema.rel, err)
		return nil
	}
	// A zero-row table is a zero-byte file; otherwise the file is exactly
	// the concatenation of newline-terminated lines (spec 11 rule 2).
	if len(data) == 0 {
		return nil
	}
	if data[len(data)-1] != '\n' {
		v.addf("E_SCHEMA_READ", "%s: file does not end with a newline", schema.rel)
		return nil
	}
	lines := bytes.Split(data[:len(data)-1], []byte{'\n'})

	var rows []map[string]any
	var prevPK string
	for i, line := range lines {
		lineNo := i + 1
		if len(line) == 0 {
			v.addf("E_SCHEMA_READ", "%s:%d: blank line", schema.rel, lineNo)
			return rows
		}
		val, err := decodeOne(line)
		if err != nil {
			v.addf("E_SCHEMA_READ", "%s:%d: not valid JSON: %v", schema.rel, lineNo, err)
			return rows
		}
		reenc, err := encodeCanonical(val)
		if err != nil {
			v.addf("E_SCHEMA_READ", "%s:%d: not canonically encodable: %v", schema.rel, lineNo, err)
			return rows
		}
		if !bytes.Equal(reenc, line) {
			v.addf("E_SCHEMA_READ", "%s:%d: line is not in canonical encoding", schema.rel, lineNo)
			return rows
		}
		rec, ok := val.(map[string]any)
		if !ok {
			v.addf("E_SCHEMA_TYPE", "%s:%d: line is not a JSON object", schema.rel, lineNo)
			return rows
		}
		if !v.checkRecordSchema(schema, rec, lineNo) {
			return rows
		}

		pk := rec[schema.primaryKey].(string)
		if i > 0 {
			if pk == prevPK {
				v.addf("E_SCHEMA_READ", "%s:%d: duplicate primary key %s", schema.rel, lineNo, pk)
				return rows
			}
			if pk < prevPK { // Go string comparison is bytewise
				v.addf("E_SCHEMA_READ", "%s:%d: rows not sorted bytewise ascending by %s",
					schema.rel, lineNo, schema.primaryKey)
				return rows
			}
		}
		prevPK = pk
		rows = append(rows, rec)
	}
	return rows
}

// checkRecordSchema enforces the exact key set, value types and enums of
// spec section 11 for one record. Returns false if an error was reported.
func (v *verifier) checkRecordSchema(schema tableSchema, rec map[string]any, lineNo int) bool {
	ok := true
	for key := range rec {
		if _, expected := schema.fields[key]; !expected {
			v.addf("E_SCHEMA_TYPE", "%s:%d: unexpected key %q", schema.rel, lineNo, key)
			ok = false
		}
	}
	for key, kind := range schema.fields {
		val, present := rec[key]
		if !present || val == nil {
			v.addf("E_SCHEMA_NULL", "%s:%d: required key %q missing or null", schema.rel, lineNo, key)
			ok = false
			continue
		}
		switch kind {
		case fieldString:
			if _, isStr := val.(string); !isStr {
				v.addf("E_SCHEMA_TYPE", "%s:%d: key %q must be a string", schema.rel, lineNo, key)
				ok = false
			}
		case fieldInt:
			if _, isNum := val.(json.Number); !isNum {
				v.addf("E_SCHEMA_TYPE", "%s:%d: key %q must be an integer", schema.rel, lineNo, key)
				ok = false
			}
		}
	}
	if !ok {
		return false
	}

	// Primary-key syntax (spec 10.2 / 10.6). The spec names no explicit
	// error code for a malformed p1_/s1_ id; E_SCHEMA_TYPE ("value of the
	// wrong type") is this implementation's reading — see FINDINGS.md.
	pk := rec[schema.primaryKey].(string)
	if re := idSyntaxRe[schema.primaryKey]; !re.MatchString(pk) {
		v.addf("E_SCHEMA_TYPE", "%s:%d: %s %q violates its syntax", schema.rel, lineNo, schema.primaryKey, pk)
		return false
	}

	// Enums (spec 11.2).
	if schema.rel == "graph/claims.jsonl" {
		if ot := rec["object_type"].(string); !validObjectTypes[ot] {
			v.addf("E_SCHEMA_ENUM", "%s:%d: object_type %q not in the allowed set", schema.rel, lineNo, ot)
			return false
		}
		tier, err := rec["tier"].(json.Number).Int64()
		if err != nil || tier < 0 || tier > 4 {
			v.addf("E_SCHEMA_ENUM", "%s:%d: tier %v outside 0-4", schema.rel, lineNo, rec["tier"])
			return false
		}
	}
	return true
}

// Stage 7 — identifier recomputation (spec section 10).
func (v *verifier) checkIdentifiers() {
	// Spec 10.3: the namespace in the entity-id preimage is the shard's
	// metadata.namespace (see FINDINGS.md on the per-row namespace field).
	namespace := stringAt(v.manifest, "metadata", "namespace")

	for i, rec := range v.entities {
		stored := rec["entity_id"].(string)
		want, err := EntityID(namespace, rec["label"].(string))
		if err != nil {
			v.addf("E_ID_ENTITY", "graph/entities.jsonl row %d: cannot recompute entity_id: %v", i+1, err)
			continue
		}
		if stored != want {
			v.addf("E_ID_ENTITY", "graph/entities.jsonl row %d: stored entity_id %s != recomputed %s",
				i+1, stored, want)
		}
	}

	for i, rec := range v.claims {
		stored := rec["claim_id"].(string)
		want, err := ClaimID(rec["subject"].(string), rec["predicate"].(string),
			rec["object_type"].(string), rec["object"].(string))
		if err != nil {
			v.addf("E_ID_CLAIM", "graph/claims.jsonl row %d: cannot recompute claim_id: %v", i+1, err)
			continue
		}
		if stored != want {
			v.addf("E_ID_CLAIM", "graph/claims.jsonl row %d: stored claim_id %s != recomputed %s",
				i+1, stored, want)
		}
	}
}

// Stage 8 — references and evidence invariants (spec sections 11–12).
func (v *verifier) checkReferences() {
	entityIDs := map[string]bool{}
	for _, rec := range v.entities {
		entityIDs[rec["entity_id"].(string)] = true
	}
	claimIDs := map[string]bool{}
	for _, rec := range v.claims {
		claimIDs[rec["claim_id"].(string)] = true
	}

	for i, rec := range v.claims {
		if subj := rec["subject"].(string); !entityIDs[subj] {
			v.addf("E_REF_ORPHAN", "graph/claims.jsonl row %d: subject %s not in entities", i+1, subj)
		}
		if rec["object_type"].(string) == "entity" {
			if obj := rec["object"].(string); !entityIDs[obj] {
				v.addf("E_REF_ORPHAN", "graph/claims.jsonl row %d: object %s not in entities", i+1, obj)
			}
		}
	}

	for i, rec := range v.provenance {
		if cid := rec["claim_id"].(string); !claimIDs[cid] {
			v.addf("E_REF_ORPHAN", "graph/provenance.jsonl row %d: claim_id %s not in claims", i+1, cid)
		}
		v.checkByteRange("graph/provenance.jsonl", i+1, rec, false)
	}

	for i, rec := range v.spans {
		v.checkByteRange("evidence/spans.jsonl", i+1, rec, true)
	}
}

// checkByteRange enforces spec section 12 for one provenance or span row;
// for spans it additionally checks the UTF-8 decoding and text equality.
func (v *verifier) checkByteRange(table string, rowNo int, rec map[string]any, isSpan bool) {
	hash := rec["source_hash"].(string)
	relpath, known := v.hashToPath[hash]
	if !known {
		v.addf("E_REF_SOURCE", "%s row %d: source_hash %s matches no file under content/", table, rowNo, hash)
		return
	}
	start, err1 := rec["byte_start"].(json.Number).Int64()
	end, err2 := rec["byte_end"].(json.Number).Int64()
	if err1 != nil || err2 != nil {
		v.addf("E_REF_SOURCE", "%s row %d: byte offsets out of integer range", table, rowNo)
		return
	}
	size := v.fileSize[relpath]
	if start < 0 || start > end || end > size {
		v.addf("E_REF_SOURCE", "%s row %d: byte range [%d,%d) invalid for %s (%d bytes)",
			table, rowNo, start, end, relpath, size)
		return
	}
	if !isSpan {
		return
	}
	content, err := os.ReadFile(v.shardFile(relpath))
	if err != nil {
		v.addf("E_REF_READ", "%s row %d: cannot read %s: %v", table, rowNo, relpath, err)
		return
	}
	slice := content[start:end]
	if !utf8.Valid(slice) {
		v.addf("E_REF_SOURCE", "%s row %d: bytes [%d,%d) of %s are not valid UTF-8",
			table, rowNo, start, end, relpath)
		return
	}
	if string(slice) != rec["text"].(string) {
		v.addf("E_REF_SOURCE", "%s row %d: text does not equal bytes [%d,%d) of %s",
			table, rowNo, start, end, relpath)
	}
}
