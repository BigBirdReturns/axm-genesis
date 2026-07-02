package axm

import (
	"bytes"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	hex64Re     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	profileRe   = regexp.MustCompile(`^[a-z][a-z0-9-]*@[1-9][0-9]*$`)
	shardIDRe   = regexp.MustCompile(`^sh1_[0-9a-f]{64}$`)
	createdAtRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z$`)
)

// manifestTopKeys is the closed top-level key set of spec 6.3.
var manifestTopKeys = map[string]bool{
	"spec_version": true, "suite": true, "metadata": true, "publisher": true,
	"license": true, "sources": true, "integrity": true, "statistics": true,
	"profiles": true, "extensions": true, "supersedes": true,
}

// Stage 2 — manifest (spec sections 5 and 6).
func (v *verifier) checkManifest() {
	raw, err := os.ReadFile(v.shardFile("manifest.json"))
	if err != nil {
		v.addf("E_MANIFEST_SYNTAX", "cannot read manifest.json: %v", err)
		return
	}
	v.manifestBytes = raw

	val, err := decodeOne(raw)
	if err != nil {
		v.addf("E_MANIFEST_SYNTAX", "manifest.json is not valid JSON: %v", err)
		return
	}
	obj, ok := val.(map[string]any)
	if !ok {
		v.addf("E_MANIFEST_SCHEMA", "manifest.json is not a JSON object")
		return
	}
	v.manifest = obj

	// Byte-exact canonical encoding (spec section 6): parse and re-encode.
	reenc, err := encodeCanonical(val)
	if err != nil {
		v.addf("E_MANIFEST_SCHEMA", "manifest.json is not canonically encodable: %v", err)
		return
	}
	if !bytes.Equal(reenc, raw) {
		v.addf("E_MANIFEST_SCHEMA", "manifest.json is not in canonical encoding (re-encoded bytes differ)")
		return
	}

	// Forbidden shard_id, closed top-level key set (spec 6.3).
	if _, present := obj["shard_id"]; present {
		v.addf("E_MANIFEST_SCHEMA", "manifest contains forbidden shard_id field (identity is derived)")
	}
	for k := range obj {
		if !manifestTopKeys[k] && k != "shard_id" {
			v.addf("E_MANIFEST_SCHEMA", "unknown top-level manifest key %q", k)
		}
	}

	// Required scalar fields (spec 6.1).
	if s, ok := obj["spec_version"].(string); !ok || s != "1.0.0" {
		v.addf("E_MANIFEST_SCHEMA", "spec_version must equal \"1.0.0\"")
	}
	if s, ok := obj["suite"].(string); !ok || s != "axm-hybrid1" {
		v.addf("E_MANIFEST_SCHEMA", "suite must equal \"axm-hybrid1\"")
	}

	v.requireSubObject(obj, "metadata", map[string]func(any) bool{
		"title":      nonEmptyString,
		"namespace":  nonEmptyString,
		"created_at": validCreatedAt,
	})
	v.requireSubObject(obj, "publisher", map[string]func(any) bool{
		"id":   nonEmptyString,
		"name": nonEmptyString,
	})
	v.requireSubObject(obj, "license", map[string]func(any) bool{
		"spdx": nonEmptyString,
	})

	// integrity: algorithm and merkle_root. Spec 6.3 grants extra members
	// only to metadata/publisher/license, so integrity is closed.
	if integ, ok := obj["integrity"].(map[string]any); !ok {
		v.addf("E_MANIFEST_SCHEMA", "integrity must be an object")
	} else {
		if s, ok := integ["algorithm"].(string); !ok || s != "blake3" {
			v.addf("E_MANIFEST_SCHEMA", "integrity.algorithm must equal \"blake3\"")
		}
		if s, ok := integ["merkle_root"].(string); !ok || !hex64Re.MatchString(s) {
			v.addf("E_MANIFEST_SCHEMA", "integrity.merkle_root must be 64 lowercase hex characters")
		}
		for k := range integ {
			if k != "algorithm" && k != "merkle_root" {
				v.addf("E_MANIFEST_SCHEMA", "unexpected key integrity.%s", k)
			}
		}
	}

	// statistics: entities and claims (row-count equality is stage 9).
	if stats, ok := obj["statistics"].(map[string]any); !ok {
		v.addf("E_MANIFEST_SCHEMA", "statistics must be an object")
	} else {
		for _, k := range []string{"entities", "claims"} {
			if _, ok := stats[k].(json.Number); !ok {
				v.addf("E_MANIFEST_SCHEMA", "statistics.%s must be an integer", k)
			}
		}
		for k := range stats {
			if k != "entities" && k != "claims" {
				v.addf("E_MANIFEST_SCHEMA", "unexpected key statistics.%s", k)
			}
		}
	}

	v.checkManifestSources(obj)
	v.checkManifestOptionals(obj)
}

func (v *verifier) requireSubObject(obj map[string]any, name string, fields map[string]func(any) bool) {
	sub, ok := obj[name].(map[string]any)
	if !ok {
		v.addf("E_MANIFEST_SCHEMA", "%s must be an object", name)
		return
	}
	for field, valid := range fields {
		if !valid(sub[field]) {
			v.addf("E_MANIFEST_SCHEMA", "%s.%s missing or invalid", name, field)
		}
	}
	// metadata/publisher/license MAY carry additional members (spec 6.3).
}

func nonEmptyString(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// validCreatedAt enforces spec 6.1: RFC 3339 date-time in UTC with the 'Z'
// designator (a numeric offset MUST be rejected); fractional seconds are
// permitted. The regex pins the surface form (uppercase T and Z, no
// offset); time.Parse validates the calendar values.
func validCreatedAt(v any) bool {
	s, ok := v.(string)
	if !ok || !createdAtRe.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

// checkManifestSources validates the syntactic rules of spec 6.4 (the
// filesystem side of the bijection is stage 5).
func (v *verifier) checkManifestSources(obj map[string]any) {
	sources, ok := obj["sources"].([]any)
	if !ok || len(sources) == 0 {
		v.addf("E_MANIFEST_SCHEMA", "sources must be a non-empty array")
		return
	}
	seenPaths := map[string]bool{}
	for i, e := range sources {
		entry, ok := e.(map[string]any)
		if !ok {
			v.addf("E_MANIFEST_SCHEMA", "sources[%d] must be an object", i)
			continue
		}
		if len(entry) != 2 {
			v.addf("E_MANIFEST_SCHEMA", "sources[%d] must have exactly the keys path and hash", i)
		}
		p, ok := entry["path"].(string)
		if !ok || !validSourcePath(p) {
			v.addf("E_MANIFEST_SCHEMA", "sources[%d].path missing or invalid", i)
		} else {
			if seenPaths[p] {
				v.addf("E_MANIFEST_SCHEMA", "sources lists %s twice", p)
			}
			seenPaths[p] = true
		}
		if h, ok := entry["hash"].(string); !ok || !hex64Re.MatchString(h) {
			v.addf("E_MANIFEST_SCHEMA", "sources[%d].hash must be 64 lowercase hex characters", i)
		}
	}
}

// validSourcePath: POSIX relative path beginning with "content/", no "."
// or ".." segments, no empty segments, no backslashes, no leading '/',
// no NUL (spec 6.4).
func validSourcePath(p string) bool {
	if !strings.HasPrefix(p, "content/") {
		return false
	}
	if strings.ContainsAny(p, "\\\x00") {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

func (v *verifier) checkManifestOptionals(obj map[string]any) {
	// profiles: non-empty array of unique profile identifiers (spec 6.2).
	if raw, present := obj["profiles"]; present {
		arr, ok := raw.([]any)
		if !ok || len(arr) == 0 {
			v.addf("E_MANIFEST_SCHEMA", "profiles must be a non-empty array of strings")
		} else {
			seen := map[string]bool{}
			for i, e := range arr {
				s, ok := e.(string)
				if !ok || !profileRe.MatchString(s) {
					v.addf("E_MANIFEST_SCHEMA", "profiles[%d] is not a valid profile identifier", i)
					continue
				}
				if seen[s] {
					v.addf("E_MANIFEST_SCHEMA", "profiles lists %q twice", s)
				}
				seen[s] = true
			}
		}
	}

	// extensions: tied to ext/ contents (spec 6.2, section 16).
	extNonEmpty := false
	for _, f := range v.files {
		if strings.HasPrefix(f, "ext/") {
			extNonEmpty = true
			break
		}
	}
	raw, present := obj["extensions"]
	switch {
	case present && !extNonEmpty:
		v.addf("E_MANIFEST_SCHEMA", "extensions present but ext/ is empty or absent")
	case !present && extNonEmpty:
		v.addf("E_MANIFEST_SCHEMA", "ext/ is non-empty but extensions is absent")
	case present:
		arr, ok := raw.([]any)
		if !ok || len(arr) == 0 {
			v.addf("E_MANIFEST_SCHEMA", "extensions must be a non-empty array of strings")
		} else {
			for i, e := range arr {
				s, ok := e.(string)
				if !ok || !profileRe.MatchString(s) {
					v.addf("E_MANIFEST_SCHEMA", "extensions[%d] is not a valid extension identifier", i)
				}
			}
		}
	}

	// supersedes: non-empty array of unique sh1_ identifiers (spec 6.2).
	if raw, present := obj["supersedes"]; present {
		arr, ok := raw.([]any)
		if !ok || len(arr) == 0 {
			v.addf("E_MANIFEST_SCHEMA", "supersedes must be a non-empty array of strings")
		} else {
			seen := map[string]bool{}
			for i, e := range arr {
				s, ok := e.(string)
				if !ok || !shardIDRe.MatchString(s) {
					v.addf("E_MANIFEST_SCHEMA", "supersedes[%d] is not a valid sh1_ shard identity", i)
					continue
				}
				if seen[s] {
					v.addf("E_MANIFEST_SCHEMA", "supersedes lists %q twice", s)
				}
				seen[s] = true
			}
		}
	}
}

// intAt reads a nested json.Number as int64.
func intAt(m map[string]any, keys ...string) (int64, bool) {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur = obj[k]
	}
	n, ok := cur.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil {
		return 0, false
	}
	return i, true
}
