package axm

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/text/unicode/norm"
)

// ErrNULInput is returned by Canonicalize for input containing U+0000.
// NUL is the field separator inside identifier preimages (spec 10.1).
var ErrNULInput = errors.New("input contains U+0000 (NUL)")

// isFrozenWS reports membership in the frozen whitespace set WS of spec
// section 10.1 (the non-Cc Unicode whitespace characters, enumerated so the
// function is independent of future Unicode changes).
func isFrozenWS(r rune) bool {
	switch {
	case r == 0x0020, r == 0x00A0, r == 0x1680:
		return true
	case r >= 0x2000 && r <= 0x200A:
		return true
	case r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000:
		return true
	}
	return false
}

// isCc reports Unicode general category Cc, which spec 10.1 pins to
// exactly U+0000–U+001F and U+007F–U+009F.
func isCc(r rune) bool {
	return r <= 0x1F || (r >= 0x7F && r <= 0x9F)
}

// Canonicalize implements canonicalize() of spec section 10.1:
//  1. NFC-normalize (Unicode 15.1.0 pin; stable under the Unicode
//     Normalization Stability Policy).
//  2. ASCII-only lowercasing (A–Z → a–z, nothing else).
//  3. Strip category-Cc control characters.
//  4. Collapse runs of frozen-set whitespace to one ASCII space; trim.
//
// Input containing U+0000 is rejected with ErrNULInput.
func Canonicalize(s string) (string, error) {
	if strings.IndexByte(s, 0) >= 0 {
		return "", ErrNULInput
	}
	s = norm.NFC.String(s)
	var b strings.Builder
	pendingSpace := false
	started := false
	for _, r := range s {
		switch {
		case isCc(r):
			// stripped; does not become a space
		case isFrozenWS(r):
			pendingSpace = true
		default:
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			if started && pendingSpace {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
			started = true
			pendingSpace = false
		}
	}
	return b.String(), nil
}

// base32lower: RFC 4648 section 6 base32, lowercased, '=' padding removed.
var b32lower = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

func idDigest(prefix string, preimage []byte) string {
	sum := sha256.Sum256(preimage)
	return prefix + b32lower.EncodeToString(sum[:])
}

// EntityID derives an entity identifier per spec 10.3.
func EntityID(namespace, label string) (string, error) {
	ns, err := Canonicalize(namespace)
	if err != nil {
		return "", err
	}
	lb, err := Canonicalize(label)
	if err != nil {
		return "", err
	}
	return idDigest("e1_", []byte(ns+"\x00"+lb)), nil
}

// ClaimID derives a claim identifier per spec 10.4. subject and (for
// object_type "entity") object are entity_id strings used verbatim;
// predicate and literal objects are canonicalized; object_type is verbatim.
func ClaimID(subject, predicate, objectType, object string) (string, error) {
	p, err := Canonicalize(predicate)
	if err != nil {
		return "", err
	}
	ov := object
	if objectType != "entity" {
		ov, err = Canonicalize(object)
		if err != nil {
			return "", err
		}
	}
	return idDigest("c1_", []byte(subject+"\x00"+p+"\x00"+objectType+"\x00"+ov)), nil
}

// ProvenanceID implements the RECOMMENDED derivation of spec 10.6.
// The kernel verifier does not recompute p1_ ids; this exists to reproduce
// the identity conformance vectors.
func ProvenanceID(claimID, sourceHash string, byteStart, byteEnd int64) string {
	pre := claimID + "\x00" + sourceHash + "\x00" +
		strconv.FormatInt(byteStart, 10) + "\x00" + strconv.FormatInt(byteEnd, 10)
	return idDigest("p1_", []byte(pre))
}

// SpanID implements the RECOMMENDED derivation of spec 10.6.
func SpanID(sourceHash string, byteStart, byteEnd int64, text string) string {
	pre := sourceHash + "\x00" +
		strconv.FormatInt(byteStart, 10) + "\x00" + strconv.FormatInt(byteEnd, 10) +
		"\x00" + text
	return idDigest("s1_", []byte(pre))
}
