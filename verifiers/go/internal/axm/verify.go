package axm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
)

// ErrorItem is one entry of the result's errors array. Code is normative
// (spec section 14); Message is free text.
type ErrorItem struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is the machine-readable verification result of spec 13.3.
type Result struct {
	Shard             string      `json:"shard"`
	Status            string      `json:"status"`
	ErrorCount        int         `json:"error_count"`
	Errors            []ErrorItem `json:"errors"`
	ProfilesChecked   []string    `json:"profiles_checked"`
	ProfilesUnchecked []string    `json:"profiles_unchecked"`
}

// StructuralCodes is the exit-2 class of spec 13.4: a FAIL where every
// reported error code is in this set means "structurally malformed".
var StructuralCodes = map[string]bool{
	"E_LAYOUT_MISSING": true,
	"E_SCHEMA_MISSING": true,
	"E_SIG_MISSING":    true,
}

// ExitCode maps a Result to the frozen CLI exit-code contract (spec 13.4).
func (r *Result) ExitCode() int {
	if r.Status == "PASS" {
		return 0
	}
	for _, e := range r.Errors {
		if !StructuralCodes[e.Code] {
			return 1
		}
	}
	return 2
}

// implementedProfiles lists the profiles this verifier implements and runs
// when a manifest declares them (spec section 15).
var implementedProfiles = map[string]func(v *verifier) []ErrorItem{
	"embodied@1": checkEmbodied1,
}

type verifier struct {
	dir  string // shard path as given
	errs []ErrorItem

	// populated by the layout stage
	files    []string // relpaths (POSIX) of every regular file, sorted bytewise
	fileSize map[string]int64

	// populated by the manifest stage
	manifest      map[string]any
	manifestBytes []byte

	// populated by the sources stage: sha256 hex -> one relpath having it
	hashToPath map[string]string

	// populated by the tables stage
	entities   []map[string]any
	claims     []map[string]any
	provenance []map[string]any
	spans      []map[string]any
}

func (v *verifier) addf(code, format string, args ...any) {
	v.errs = append(v.errs, ErrorItem{Code: code, Message: fmt.Sprintf(format, args...)})
}

// Verify runs the full kernel verification procedure of spec 13.2 plus the
// implemented profiles, against a trusted 1344-byte hybrid public key
// supplied out of band. Stages run in the reference order and verification
// stops at the first failing stage (a single run reports the errors of one
// stage), which spec 13.2 documents as the reference behavior and the
// vector suite expects.
func Verify(shardPath string, trustedKey []byte) *Result {
	v := &verifier{dir: shardPath, fileSize: map[string]int64{}}

	stages := []func(trustedKey []byte){
		func(_ []byte) { v.checkLayout() },
		func(_ []byte) { v.checkManifest() },
		v.checkSignature,
		func(_ []byte) { v.checkMerkle() },
		func(_ []byte) { v.checkSources() },
		func(_ []byte) { v.checkTables() },
		func(_ []byte) { v.checkIdentifiers() },
		func(_ []byte) { v.checkReferences() },
		func(_ []byte) { v.checkStatistics() },
	}

	kernelFailed := false
	for _, stage := range stages {
		stage(trustedKey)
		if len(v.errs) > 0 {
			kernelFailed = true
			break
		}
	}

	// Profiles (spec section 15): run every declared profile we implement,
	// unless the kernel already failed; declared-but-not-run profiles are
	// reported unchecked (unchecked is not passed).
	checked := []string{}
	declared := v.declaredProfiles()
	if !kernelFailed {
		for _, p := range declared {
			if run, ok := implementedProfiles[p]; ok {
				v.errs = append(v.errs, run(v)...)
				checked = append(checked, p)
			}
		}
	}
	unchecked := []string{}
	for _, p := range declared {
		found := false
		for _, c := range checked {
			if c == p {
				found = true
			}
		}
		if !found {
			unchecked = append(unchecked, p)
		}
	}

	res := &Result{
		Shard:             shardPath,
		Status:            "PASS",
		Errors:            v.errs,
		ErrorCount:        len(v.errs),
		ProfilesChecked:   checked,
		ProfilesUnchecked: unchecked,
	}
	if res.Errors == nil {
		res.Errors = []ErrorItem{}
	}
	if len(res.Errors) > 0 {
		res.Status = "FAIL"
	}
	return res
}

// declaredProfiles returns the manifest's profiles array if the manifest
// was parsed and the field is a well-formed string array; empty otherwise.
func (v *verifier) declaredProfiles() []string {
	if v.manifest == nil {
		return nil
	}
	raw, ok := v.manifest["profiles"].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Stage 1 — layout (spec section 4)

func (v *verifier) checkLayout() {
	st, err := os.Lstat(v.dir)
	if err != nil || !st.IsDir() {
		v.addf("E_LAYOUT_MISSING", "shard path %q does not exist or is not a directory", v.dir)
		return
	}

	root := os.DirFS(v.dir)
	err = fs.WalkDir(root, ".", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			v.addf("E_LAYOUT_DIRTY", "cannot walk %s: %v", p, walkErr)
			return fs.SkipDir
		}
		if p == "." {
			return nil
		}
		name := path.Base(p)
		if strings.HasPrefix(name, ".") {
			v.addf("E_DOTFILE", "dotfile in shard tree: %s", p)
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			v.addf("E_LAYOUT_DIRTY", "symlink in shard tree: %s", p)
		case d.IsDir():
			// directories themselves are checked via the closed sets below
		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				v.addf("E_LAYOUT_DIRTY", "cannot stat %s: %v", p, err)
				return nil
			}
			v.files = append(v.files, p)
			v.fileSize[p] = info.Size()
		default:
			v.addf("E_LAYOUT_DIRTY", "non-regular file in shard tree: %s", p)
		}
		return nil
	})
	if err != nil {
		v.addf("E_LAYOUT_DIRTY", "walk failed: %v", err)
		return
	}
	sort.Strings(v.files)

	// Closed root item set.
	rootEntries, err := fs.ReadDir(root, ".")
	if err != nil {
		v.addf("E_LAYOUT_MISSING", "cannot read shard directory: %v", err)
		return
	}
	seen := map[string]fs.DirEntry{}
	for _, e := range rootEntries {
		seen[e.Name()] = e
		switch e.Name() {
		case "manifest.json", "sig", "content", "graph", "evidence", "ext":
			// expected
		default:
			if !strings.HasPrefix(e.Name(), ".") { // dotfiles already reported
				v.addf("E_LAYOUT_DIRTY", "unexpected item at shard root: %s", e.Name())
			}
		}
	}
	requireFile := func(name string) {
		e, ok := seen[name]
		if !ok || e.IsDir() {
			v.addf("E_LAYOUT_MISSING", "required file %s absent", name)
		}
	}
	requireDir := func(name string) bool {
		e, ok := seen[name]
		if !ok || !e.IsDir() {
			v.addf("E_LAYOUT_MISSING", "required directory %s/ absent", name)
			return false
		}
		return true
	}
	requireFile("manifest.json")

	// sig/: exactly manifest.sig and publisher.pub.
	if requireDir("sig") {
		want := map[string]bool{"manifest.sig": true, "publisher.pub": true}
		entries, _ := fs.ReadDir(root, "sig")
		got := map[string]bool{}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if !want[e.Name()] || e.IsDir() {
				v.addf("E_LAYOUT_DIRTY", "unexpected item in sig/: %s", e.Name())
				continue
			}
			got[e.Name()] = true
		}
		for name := range want {
			if !got[name] {
				v.addf("E_SIG_MISSING", "sig/%s absent", name)
			}
		}
	}

	// graph/ and evidence/: exactly the core table files.
	checkTablesDir := func(dir string, want []string) {
		if !requireDir(dir) {
			return
		}
		wanted := map[string]bool{}
		for _, w := range want {
			wanted[w] = true
		}
		entries, _ := fs.ReadDir(root, dir)
		got := map[string]bool{}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".") {
				continue
			}
			if !wanted[e.Name()] || e.IsDir() {
				v.addf("E_LAYOUT_DIRTY", "unexpected item in %s/: %s", dir, e.Name())
				continue
			}
			got[e.Name()] = true
		}
		for _, w := range want {
			if !got[w] {
				v.addf("E_SCHEMA_MISSING", "required table %s/%s absent", dir, w)
			}
		}
	}
	checkTablesDir("graph", []string{"entities.jsonl", "claims.jsonl", "provenance.jsonl"})
	checkTablesDir("evidence", []string{"spans.jsonl"})

	// content/: at least one regular file (recursively).
	if requireDir("content") {
		hasFile := false
		for _, f := range v.files {
			if strings.HasPrefix(f, "content/") {
				hasFile = true
				break
			}
		}
		if !hasFile {
			v.addf("E_LAYOUT_MISSING", "content/ contains no regular file")
		}
	}
}

// ---------------------------------------------------------------------------
// Stage 3 — signature suite axm-hybrid1 (spec section 7)

const sigDomainPrefix = "axm-genesis/v1/manifest\x00"

func (v *verifier) checkSignature(trustedKey []byte) {
	pub, err := os.ReadFile(v.shardFile("sig/publisher.pub"))
	if err != nil {
		v.addf("E_SIG_MISSING", "cannot read sig/publisher.pub: %v", err)
		return
	}
	sig, err := os.ReadFile(v.shardFile("sig/manifest.sig"))
	if err != nil {
		v.addf("E_SIG_MISSING", "cannot read sig/manifest.sig: %v", err)
		return
	}
	if len(pub) != 1344 {
		v.addf("E_SIG_INVALID", "sig/publisher.pub is %d bytes, want 1344", len(pub))
		return
	}
	if len(sig) != 2484 {
		v.addf("E_SIG_INVALID", "sig/manifest.sig is %d bytes, want 2484", len(sig))
		return
	}
	if !bytes.Equal(pub, trustedKey) {
		v.addf("E_SIG_INVALID", "embedded sig/publisher.pub differs from the trusted key")
		return
	}

	msg := append([]byte(sigDomainPrefix), v.manifestBytes...)

	edOK := ed25519.Verify(ed25519.PublicKey(pub[:32]), msg, sig[:64])

	mlOK := false
	var mpk mldsa44.PublicKey
	if err := mpk.UnmarshalBinary(pub[32:]); err == nil {
		// FIPS 204 pure ML-DSA-44, empty context string.
		mlOK = mldsa44.Verify(&mpk, msg, nil, sig[64:])
	}

	if !edOK || !mlOK {
		var failed []string
		if !edOK {
			failed = append(failed, "ed25519")
		}
		if !mlOK {
			failed = append(failed, "ml-dsa-44")
		}
		v.addf("E_SIG_INVALID", "hybrid signature verification failed (%s); both components must verify",
			strings.Join(failed, ", "))
	}
}

// ---------------------------------------------------------------------------
// Stage 4 — Merkle root (spec section 8)

func (v *verifier) checkMerkle() {
	var covered []string
	for _, f := range v.files {
		if f == "manifest.json" || strings.HasPrefix(f, "sig/") {
			continue
		}
		covered = append(covered, f)
	}
	// v.files is already sorted bytewise ascending.
	root, err := merkleRootOfShard(v.dir, covered)
	if err != nil {
		v.addf("E_REF_READ", "cannot hash covered files: %v", err)
		return
	}
	want := stringAt(v.manifest, "integrity", "merkle_root")
	got := hex.EncodeToString(root[:])
	if got != want {
		v.addf("E_MERKLE_MISMATCH", "computed Merkle root %s != manifest integrity.merkle_root %s", got, want)
	}
}

// ---------------------------------------------------------------------------
// Stage 5 — sources bijection with content/ (spec 6.4)

func (v *verifier) checkSources() {
	v.hashToPath = map[string]string{}
	actual := map[string]string{} // relpath -> sha256 hex
	for _, f := range v.files {
		if !strings.HasPrefix(f, "content/") {
			continue
		}
		sum, err := sha256File(v.shardFile(f))
		if err != nil {
			v.addf("E_REF_READ", "cannot hash %s: %v", f, err)
			return
		}
		actual[f] = sum
		v.hashToPath[sum] = f
	}

	declared := map[string]bool{}
	sources, _ := v.manifest["sources"].([]any)
	for i, e := range sources {
		obj, _ := e.(map[string]any)
		p, _ := obj["path"].(string)
		h, _ := obj["hash"].(string)
		declared[p] = true
		got, exists := actual[p]
		switch {
		case !exists:
			v.addf("E_MANIFEST_SCHEMA", "sources[%d]: %s not found under content/", i, p)
		case got != h:
			v.addf("E_MANIFEST_SCHEMA", "sources[%d]: %s SHA-256 %s != declared %s", i, p, got, h)
		}
	}
	for p := range actual {
		if !declared[p] {
			v.addf("E_MANIFEST_SCHEMA", "content file %s not listed in sources (bijection violated)", p)
		}
	}
}

func sha256File(fsPath string) (string, error) {
	data, err := os.ReadFile(fsPath)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Stage 9 — statistics (spec 6.1)

func (v *verifier) checkStatistics() {
	wantEnt, ok1 := intAt(v.manifest, "statistics", "entities")
	wantClaims, ok2 := intAt(v.manifest, "statistics", "claims")
	if !ok1 || !ok2 {
		v.addf("E_MANIFEST_SCHEMA", "statistics counts unreadable")
		return
	}
	if wantEnt != int64(len(v.entities)) {
		v.addf("E_MANIFEST_SCHEMA", "statistics.entities = %d but graph/entities.jsonl has %d rows",
			wantEnt, len(v.entities))
	}
	if wantClaims != int64(len(v.claims)) {
		v.addf("E_MANIFEST_SCHEMA", "statistics.claims = %d but graph/claims.jsonl has %d rows",
			wantClaims, len(v.claims))
	}
}

// ---------------------------------------------------------------------------
// helpers

func (v *verifier) shardFile(rel string) string {
	return v.dir + string(os.PathSeparator) + strings.ReplaceAll(rel, "/", string(os.PathSeparator))
}

func stringAt(m map[string]any, keys ...string) string {
	cur := any(m)
	for _, k := range keys {
		obj, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = obj[k]
	}
	s, _ := cur.(string)
	return s
}
