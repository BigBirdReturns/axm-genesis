// Package axm implements an independent verifier for the AXM Genesis v1
// shard format, built solely from spec/v1/SPECIFICATION.md, spec/v1/
// CONFORMANCE.md, spec/profiles/embodied@1.md, COMPATIBILITY.md and the
// conformance vectors under tests/vectors/ — with no access to the
// reference implementation.
package axm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
)

// canonicalIntRe matches the shortest decimal form of a non-negative
// integer (spec section 5 rule 4): no leading zeros, no '+', no fraction,
// no exponent, no '-0' (in fact no negatives at all in kernel documents).
var canonicalIntRe = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// errNonCanonicalNumber is returned when a JSON number literal has no
// canonical encoding under spec section 5 (float, negative, exponent,
// leading zeros, or out of [0, 2^63-1]).
var errNonCanonicalNumber = errors.New("number has no canonical encoding")

// decodeOne parses exactly one JSON value from data, preserving number
// literals as json.Number. Trailing non-whitespace content is an error.
// (Trailing *whitespace* is tolerated here and caught by the byte-exact
// canonical-form comparison instead.)
func decodeOne(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

// encodeCanonical serializes an abstract JSON value to the canonical byte
// encoding of spec section 5. Notes:
//   - Object keys are sorted by Unicode code point, which for UTF-8 encoded
//     Go strings equals bytewise order (Go's sort.Strings).
//   - json.Number literals must already be in canonical integer form;
//     anything else has no canonical encoding and yields an error.
//   - nil (JSON null) is emitted literally as "null" so that the canonical
//     form check can pass and the schema layer can report the more precise
//     E_SCHEMA_NULL / E_MANIFEST_SCHEMA error.
func encodeCanonical(v any) ([]byte, error) {
	return appendCanonical(nil, v)
}

func appendCanonical(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case json.Number:
		s := string(x)
		if !canonicalIntRe.MatchString(s) {
			return nil, fmt.Errorf("%w: %q", errNonCanonicalNumber, s)
		}
		if _, err := strconv.ParseInt(s, 10, 64); err != nil {
			return nil, fmt.Errorf("%w: %q exceeds 2^63-1", errNonCanonicalNumber, s)
		}
		return append(dst, s...), nil
	case string:
		return appendCanonicalString(dst, x), nil
	case []any:
		dst = append(dst, '[')
		for i, e := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			dst, err = appendCanonical(dst, e)
			if err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // bytewise == code-point order for UTF-8
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendCanonicalString(dst, k)
			dst = append(dst, ':')
			var err error
			dst, err = appendCanonical(dst, x[k])
			if err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("unsupported JSON value type %T", v)
	}
}

const hexDigits = "0123456789abcdef"

// appendCanonicalString applies exactly the escapes of spec section 5
// rule 3: `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, `\u00xx` (lowercase)
// for the remaining code points below U+0020, and literal UTF-8 for
// everything else (including all non-ASCII characters and U+007F).
func appendCanonicalString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		b := s[i]
		switch {
		case b == '"':
			dst = append(dst, '\\', '"')
		case b == '\\':
			dst = append(dst, '\\', '\\')
		case b == 0x08:
			dst = append(dst, '\\', 'b')
		case b == 0x09:
			dst = append(dst, '\\', 't')
		case b == 0x0A:
			dst = append(dst, '\\', 'n')
		case b == 0x0C:
			dst = append(dst, '\\', 'f')
		case b == 0x0D:
			dst = append(dst, '\\', 'r')
		case b < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hexDigits[b>>4], hexDigits[b&0xF])
		default:
			dst = append(dst, b)
		}
	}
	return append(dst, '"')
}
